const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {execFileSync,spawnSync}=require('node:child_process');
const {scanGitIntegrity}=require('../src/git-integrity');

(async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'aport-integrity-test-'));
  const git=(...args)=>execFileSync('git',['-c','core.hooksPath=/dev/null','-C',dir,...args],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  try{
    git('init');git('config','user.name','Integrity fixture');git('config','user.email','fixture@example.invalid');git('config','commit.gpgsign','false');
    fs.mkdirSync(path.join(dir,'tests'));
    const source=path.join(dir,'tests','fixture.js');
    fs.writeFileSync(source,'const visible=1;\n');
    git('add','.');git('commit','-m','clean');const base=git('rev-parse','HEAD');
    assert.equal((await scanGitIntegrity({repository:dir,head:base})).findings.length,0);
    const sentinel=path.join(dir,'MUST_NOT_EXECUTE');
    fs.writeFileSync(source,'const visible=1;'+' '.repeat(2000)+'require("fs").writeFileSync('+JSON.stringify(sentinel)+',"executed");\n');
    git('add','.');git('commit','-m','inert concealed fixture');const injected=git('rev-parse','HEAD');
    const blocked=await scanGitIntegrity({repository:dir,head:injected,base});
    assert(blocked.text>0,'the scan must read real Git blobs');
    assert(blocked.findings.some(f=>f.rule==='padded-appended-code'),'source/test injection must fail the real Git scanner');
    assert(!fs.existsSync(sentinel),'scanning must never execute candidate source');
    fs.writeFileSync(source,'const visible=1;\n');
    git('add','.');git('commit','-m','remove fixture');const cleanTip=git('rev-parse','HEAD');
    assert((await scanGitIntegrity({repository:dir,head:cleanTip,base})).findings.length>0,
      'add-then-remove injection must remain detectable in introduced history');
    const cli=spawnSync(process.execPath,[path.join(__dirname,'../src/git-integrity.js')],{
      env:{...process.env,APORT_SCAN_REPOSITORY:dir,APORT_SCAN_HEAD:cleanTip,APORT_SCAN_BASE:base,
        APORT_MODE:'evidence-only',LABELS_JSON:'["aport-control-plane-approved"]'},encoding:'utf8',
    });
    assert.equal(cli.status,1,'CLI must fail despite evidence-only mode or approval labels');
    assert(JSON.parse(cli.stdout).findings.length>0,'CLI must report the detected historical injection');
    await assert.rejects(scanGitIntegrity({repository:dir,head:'--all'}),/exact head SHA/);
    await assert.rejects(scanGitIntegrity({repository:dir,head:cleanTip,base:'a'.repeat(40)}));
    fs.writeFileSync(path.join(dir,'.git','shallow'),cleanTip+'\n');
    await assert.rejects(scanGitIntegrity({repository:dir,head:cleanTip}),/Incomplete history/);
    console.log('OK git-integrity.test.js');
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
