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
    const afterGate=path.join(dir,'AFTER_GATE_MUST_NOT_RUN');
    const gated=spawnSync('/bin/bash',['-e','-c',
      '"$TEST_NODE" "$TEST_SCANNER"\n"$TEST_NODE" -e \'require("node:fs").writeFileSync(process.env.TEST_SENTINEL,"ran")\''],{
      env:{...process.env,APORT_SCAN_REPOSITORY:dir,APORT_SCAN_HEAD:cleanTip,APORT_SCAN_BASE:base,
        TEST_NODE:process.execPath,TEST_SCANNER:path.join(__dirname,'../src/git-integrity.js'),TEST_SENTINEL:afterGate},
      encoding:'utf8',
    });
    assert.equal(gated.status,1,'a failing integrity command must stop the execution chain');
    assert(!fs.existsSync(afterGate),'a post-gate install/test sentinel must never run on rejected history');
    fs.writeFileSync(source,'const visible=1;/*\0*/'+' '.repeat(2000)+'require("fs").writeFileSync('+JSON.stringify(sentinel)+',"executed");\n');
    git('add','.');git('commit','-m','NUL-bearing inert source fixture');
    const nulBearing=await scanGitIntegrity({repository:dir,head:git('rev-parse','HEAD'),base:cleanTip});
    assert.equal(nulBearing.binary,1,'fixture must reach the NUL-bearing blob path');
    assert(nulBearing.findings.some(f=>f.rule==='padded-appended-code'),
      'a NUL in a JavaScript comment must not skip concealed source scanning');
    fs.writeFileSync(source,'const visible=1;\n');
    await assert.rejects(scanGitIntegrity({repository:dir,head:'--all'}),/exact head SHA/);
    await assert.rejects(scanGitIntegrity({repository:dir,head:cleanTip,base:'a'.repeat(40)}));
    fs.writeFileSync(path.join(dir,'postcss.config.js'),'module.exports={name:"'+'x'.repeat(1200)+'"};\n');
    git('add','.');git('commit','-m','strict configuration fixture');
    const strict=await scanGitIntegrity({repository:dir,head:git('rev-parse','HEAD'),base:cleanTip});
    assert(strict.findings.some(f=>f.rule==='oversized-source-line'),
      'trusted Git scan must preserve existing strict configuration checks');
    const historicalConfig=path.join(dir,'postcss.config.fixture.js');
    // Inert comment; assemble the indicator so the test source is not one.
    fs.writeFileSync(historicalConfig,['// fixture: ', 'eval', '(', 'atob', '("Zml4dHVyZQ=="))\n'].join(''));
    git('add','.');git('commit','-m','historical configuration classification fixture');
    const configHead=git('rev-parse','HEAD');
    const configBlob=git('rev-parse','HEAD:postcss.config.fixture.js');
    const hasConfigFinding=result=>result.findings.some(f=>f.blob===configBlob&&f.rule==='eval-base64-decoder');
    assert(hasConfigFinding(await scanGitIntegrity({repository:dir,head:configHead})),
      'fixture must reach the strict configuration detector before deletion');
    fs.unlinkSync(historicalConfig);
    git('add','.');git('commit','-m','delete historical configuration fixture');
    const deletedConfig=git('rev-parse','HEAD');
    assert(hasConfigFinding(await scanGitIntegrity({repository:dir,head:deletedConfig})),
      'deleted configuration must keep its strict history classification');
    assert(hasConfigFinding(await scanGitIntegrity({repository:dir,head:deletedConfig,base:cleanTip})),
      'introduced history must keep deleted configuration classification');
    git('checkout','-b','renamed-config',configHead);
    git('mv','postcss.config.fixture.js','tests/renamed-config.js');
    git('commit','-m','rename configuration to an ordinary source path');
    assert(hasConfigFinding(await scanGitIntegrity({repository:dir,head:git('rev-parse','HEAD')})),
      'renamed configuration must retain strict classification through its old alias');
    // A newline in a path must not split or hide a raw Git history entry.
    git('mv','tests/renamed-config.js','tests/renamed\nconfig.js');
    git('commit','-m','rename fixture with a newline');
    assert(hasConfigFinding(await scanGitIntegrity({repository:dir,head:git('rev-parse','HEAD'),base:cleanTip})),
      'NUL-delimited history parsing must preserve configuration aliases');
    fs.writeFileSync(path.join(dir,'.git','shallow'),cleanTip+'\n');
    await assert.rejects(scanGitIntegrity({repository:dir,head:cleanTip}),/Incomplete history/);
    console.log('OK git-integrity.test.js');
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
