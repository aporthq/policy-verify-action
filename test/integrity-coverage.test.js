const assert = require('node:assert/strict');
const { detectSuspiciousContentFindings, isSuspiciousContentPath } = require('../src/structural');

const concealed = 'const visible = 1;' + ' '.repeat(2000) + 'const hidden = 2;';
const paths = [
  'tests/extensions/openclaw-aport.test.js', 'test/run.js', 'src/server/index.js',
  'examples/client.ts', 'conformance/src/runner.ts', 'nested/package/index.mjs',
  'dist/generated.js', 'worker.py', 'bin/start.sh',
];
for (const filename of paths) {
  assert(isSuspiciousContentPath(filename), `execution source must be covered: ${filename}`);
  const findings = detectSuspiciousContentFindings([{ filename }], { [filename]: concealed });
  assert(findings.some(f => f.code === 'OAP.REPO.SUSPICIOUS_OBFUSCATION'),
    `concealed code must be blocked without custom protected paths: ${filename}`);
  const missing = detectSuspiciousContentFindings([{ filename }]);
  assert(missing.some(f => f.code === 'OAP.REPO.SUSPICIOUS_CONTENT_DIFF_UNAVAILABLE'),
    `missing source evidence must fail closed: ${filename}`);
}
const generated = 'const data = "' + 'a'.repeat(5000) + '";';
assert.equal(detectSuspiciousContentFindings([{filename:'dist/generated.js'}],
  {'dist/generated.js':generated}).length, 0, 'line length alone is not malware in general source');
assert(detectSuspiciousContentFindings([{filename:'postcss.config.js'}],
  {'postcss.config.js':generated}).length, 'strict config-line rule remains active');
assert.equal(detectSuspiciousContentFindings([{filename:'public/photo.png'}]).length,0,
  'binary image without a text patch is not missing executable-source evidence');
console.log('OK integrity-coverage.test.js');
