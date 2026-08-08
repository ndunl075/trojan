#!/usr/bin/env node
/**
 * Test runner.
 *
 * `node --test "dir/*.test.js"` only expands globs on Node 22+, and
 * `node --test dir/` treats the directory as a module on some versions. Since
 * package.json claims Node >= 18, we enumerate the files ourselves and hand
 * `--test` an explicit list, which every supported version understands.
 */

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const TEST_DIR = path.join(__dirname, '..', '.test-build', 'test');

if (!fs.existsSync(TEST_DIR)) {
  console.error(`No compiled tests at ${TEST_DIR}. Run \`npm run pretest\` first.`);
  process.exit(1);
}

const files = fs
  .readdirSync(TEST_DIR)
  .filter((name) => name.endsWith('.test.js'))
  .sort()
  .map((name) => path.join(TEST_DIR, name));

if (files.length === 0) {
  console.error(`No *.test.js files found in ${TEST_DIR}.`);
  process.exit(1);
}

const args = ['--test', ...process.argv.slice(2), ...files];
const child = spawn(process.execPath, args, { stdio: 'inherit' });

child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 1);
});
