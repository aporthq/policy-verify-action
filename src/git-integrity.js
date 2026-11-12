const { execFileSync, spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { findIntegrityContentMatches, findSuspiciousContentMatches,
  isStrictContentPath, isSuspiciousContentPath } = require('./structural');

// Exact reviewed historical content, never candidate-controlled exemptions.
// Neither a path exemption nor candidate-controlled configuration may skip code.
const REVIEWED_BLOBS = new Map([
  ['af89bbed79777440bd48b2991cfb89e2d333c8c3', '3f2f9cd47589cf086c765daf0a45b56906235caf14bfd4fcbc8ef7158bdaf0d3'],
  // Sanitized PR-review JSON fixture with one long serialized comment string.
  ['c350d1669c024e68a6e56003afa1f9fd2f54b342', '82c80c4cafefdbfb8358559dfae4ec15a0d8fc08493f9b667c577aaf63452d41'],
]);
const GIT_OPTIONS = ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
  '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', '-c', 'submodule.recurse=false'];
const MAX_BLOB = 64 * 1024 * 1024;
const MAX_BYTES = 512 * 1024 * 1024;

function gitEnvironment() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith('GIT_')) delete env[key];
  return { ...env, GIT_CONFIG_NOSYSTEM:'1', GIT_CONFIG_GLOBAL:'/dev/null',
    GIT_NO_REPLACE_OBJECTS:'1', GIT_NO_LAZY_FETCH:'1', GIT_TERMINAL_PROMPT:'0' };
}

async function scanGitIntegrity({ repository, head, base = '' }) {
  if (!/^[a-f0-9]{40}$/.test(head || '')) throw new Error('An exact head SHA is required');
  if (base && !/^[a-f0-9]{40}$/.test(base)) throw new Error('Base must be an exact SHA');
  if (/^0{40}$/.test(base)) base = '';
  const options = { cwd:repository, env:gitEnvironment(), encoding:'utf8',
    maxBuffer:40*1024*1024, timeout:30000, stdio:['pipe','pipe','pipe'] };
  const git = (args, input) => execFileSync('git',[...GIT_OPTIONS,...args],{...options,input});
  if (git(['rev-parse','--is-shallow-repository']).trim() !== 'false') {
    throw new Error('Incomplete history: fetch full history before scanning');
  }
  for (const sha of [head,base].filter(Boolean)) {
    if (git(['rev-parse','--verify',`${sha}^{commit}`]).trim() !== sha) throw new Error('Commit identity mismatch');
  }
  const ids = new Set(git(['rev-list','--objects',head,...(base?['^'+base]:[])])
    .split('\n').filter(Boolean).map(line=>line.split(' ')[0]));
  const submodules = [];
  const strictBlobs = new Set();
  const recordPath = (oid, file) => {
    if (isSuspiciousContentPath(file) && isStrictContentPath(file)) strictBlobs.add(oid);
  };
  // Always inspect the full resulting tree, including reused existing blobs.
  for (const entry of git(['ls-tree','-r','-z',head]).split('\0').filter(Boolean)) {
    const match = /^(\d+) (\w+) ([a-f0-9]{40})\t/.exec(entry);
    if (!match) throw new Error('Malformed tree entry');
    if (match[2] === 'blob') {
      ids.add(match[3]);
      recordPath(match[3], entry.slice(match[0].length));
    }
    if (match[1] === '160000') submodules.push({commit:match[3],path:entry.slice(match[0].length)});
  }
  if (ids.size > 200000) throw new Error('Object budget exceeded; no successful verdict');
  // HEAD alone loses deleted/renamed config paths. Classify both sides of every
  // historical change; -m includes merge parents and -z preserves unusual names.
  // Rename detection is off so each record always has exactly one path.
  const history = git(['log','--format=','--raw','-z','--no-abbrev','--no-renames',
    '--no-ext-diff','--no-textconv','--no-show-signature','--root','-m',
    head,...(base?['^'+base]:[]),'--']).split('\0');
  for (let i = 0; i < history.length;) {
    const header = history[i++].trim();
    if (!header) continue;
    const change = /^:[0-7]{6} [0-7]{6} ([a-f0-9]{40}) ([a-f0-9]{40}) [AMDTUXB]$/.exec(header);
    const file = history[i++];
    if (!change || !file) throw new Error('Malformed historical path evidence');
    for (const oid of [change[1], change[2]]) {
      if (ids.has(oid)) recordPath(oid, file);
    }
  }
  const metadata=git(['cat-file','--batch-check=%(objectname) %(objecttype) %(objectsize)'],[...ids].join('\n')+'\n')
    .trim().split('\n').filter(Boolean).map(line=>{
      const [oid,type,size]=line.split(' ');
      if (!ids.has(oid)||!Number.isSafeInteger(Number(size))) throw new Error('Missing or invalid Git object');
      return {oid,type,size:Number(size)};
    });
  if (metadata.length !== ids.size) throw new Error('Incomplete object metadata');
  const blobs=metadata.filter(x=>x.type==='blob');
  const bytes=blobs.reduce((n,b)=>n+b.size,0);
  if (bytes>MAX_BYTES||blobs.some(b=>b.size>MAX_BLOB)) throw new Error('Content budget exceeded; no successful verdict');
  const result={head,base:base||null,coverage:base?'introduced history and complete head tree':'complete head ancestry and tree',
    blobs:blobs.length,bytes,text:0,binary:0,reviewed:0,submodules,findings:[]};
  if (!blobs.length) return result;
  const proc=spawn('git',[...GIT_OPTIONS,'cat-file','--batch'],{cwd:repository,env:options.env,stdio:['pipe','pipe','pipe']});
  let stderr='';proc.stderr.on('data',chunk=>{stderr=(stderr+chunk).slice(-4000);});
  const completed=new Promise((resolve,reject)=>{proc.on('error',reject);proc.on('close',code=>code===0?resolve():reject(new Error(stderr||'Git object read failed')));});
  // Attach a rejection handler immediately; stdout iteration may still be active.
  completed.catch(()=>{});
  proc.stdin.on('error',()=>{});
  proc.stdin.end(blobs.map(b=>b.oid).join('\n')+'\n');
  const timer=setTimeout(()=>proc.kill('SIGKILL'),120000);
  let buffer=Buffer.alloc(0),pending=null,index=0;
  try {
    for await(const chunk of proc.stdout) {
      buffer=Buffer.concat([buffer,chunk]);
      while(true) {
        if(!pending) {
          const end=buffer.indexOf(10);if(end<0)break;
          const [oid,type,size]=buffer.subarray(0,end).toString().split(' ');
          buffer=buffer.subarray(end+1);
          const expected=blobs[index];
          if(!expected||oid!==expected.oid||type!=='blob'||Number(size)!==expected.size) throw new Error('Object stream identity mismatch');
          pending=expected;
        }
        if(buffer.length<pending.size+1)break;
        if(buffer[pending.size]!==10)throw new Error('Malformed object framing');
        const body=buffer.subarray(0,pending.size);
        if(body.includes(0))result.binary++;
        else result.text++;
        // A NUL is valid inside some source comments/strings. It must not turn
        // an executable source blob into an uninspected binary exemption.
        const text=body.toString('utf8');
        const digest=createHash('sha256').update(body).digest('hex');
        if(REVIEWED_BLOBS.get(pending.oid)===digest)result.reviewed++;
        else for(const match of strictBlobs.has(pending.oid)
          ? findSuspiciousContentMatches(text)
          : findIntegrityContentMatches(text)) {
          result.findings.push({blob:pending.oid,rule:match.code,line:text.slice(0,match.index).split('\n').length});
        }
        buffer=buffer.subarray(pending.size+1);pending=null;index++;
      }
    }
    await completed;
    if(index!==blobs.length||pending||buffer.length)throw new Error('Incomplete Git object scan');
  } finally {clearTimeout(timer);if(proc.exitCode===null)proc.kill('SIGKILL');}
  return result;
}

if(require.main===module) {
  scanGitIntegrity({repository:process.env.APORT_SCAN_REPOSITORY||process.cwd(),head:process.env.APORT_SCAN_HEAD,base:process.env.APORT_SCAN_BASE})
    .then(result=>{console.log(JSON.stringify(result,null,2));if(result.findings.length)process.exitCode=1;})
    .catch(error=>{console.error('Integrity scan incomplete: '+error.message);process.exitCode=1;});
}
module.exports={scanGitIntegrity};
