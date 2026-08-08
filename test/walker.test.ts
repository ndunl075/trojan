/**
 * Filesystem-layer tests.
 *
 * The fuzzer covers rule input; this covers everything the walker has to
 * survive on disk. Symlink handling in particular is where a scanner either
 * terminates or spins forever.
 */

import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it } from 'node:test';

import { isTextCandidate, looksBinary, walk } from '../src/walker';

async function tempDir(): Promise<string> {
  return fsp.mkdtemp(path.join(os.tmpdir(), 'trojan-walk-'));
}

/** Symlink creation needs elevation on Windows; skip rather than fail there. */
async function canSymlink(dir: string): Promise<boolean> {
  try {
    await fsp.symlink(dir, path.join(dir, '__probe'), 'dir');
    await fsp.unlink(path.join(dir, '__probe'));
    return true;
  } catch {
    return false;
  }
}

describe('walker', () => {
  it('finds text files and skips binaries', async () => {
    const dir = await tempDir();
    await fsp.writeFile(path.join(dir, 'a.js'), 'const a = 1;');
    await fsp.writeFile(path.join(dir, 'b.md'), '# hi');
    await fsp.writeFile(path.join(dir, 'c.png'), Buffer.from([0x89, 0x50, 0x00, 0x01]));

    const outcome = await walk(dir, { respectGitignore: false });
    const names = outcome.files.map((f) => f.relativePath).sort();

    assert.deepEqual(names, ['a.js', 'b.md']);
    await fsp.rm(dir, { recursive: true, force: true });
  });

  it('does not follow symlinks by default', async () => {
    const dir = await tempDir();
    if (!(await canSymlink(dir))) {
      await fsp.rm(dir, { recursive: true, force: true });
      return; // Unprivileged Windows; covered on the Linux and macOS runners.
    }

    await fsp.mkdir(path.join(dir, 'real'));
    await fsp.writeFile(path.join(dir, 'real', 'a.js'), 'const a = 1;');
    await fsp.symlink(path.join(dir, 'real'), path.join(dir, 'link'), 'dir');

    const outcome = await walk(dir, { respectGitignore: false });
    assert.deepEqual(outcome.files.map((f) => f.relativePath).sort(), ['real/a.js']);

    await fsp.rm(dir, { recursive: true, force: true });
  });

  it('terminates on a symlink cycle when following links', async () => {
    const dir = await tempDir();
    if (!(await canSymlink(dir))) {
      await fsp.rm(dir, { recursive: true, force: true });
      return;
    }

    // a/b -> a, the classic infinite descent.
    await fsp.mkdir(path.join(dir, 'a'));
    await fsp.writeFile(path.join(dir, 'a', 'x.js'), 'const a = 1;');
    await fsp.symlink(path.join(dir, 'a'), path.join(dir, 'a', 'b'), 'dir');

    const outcome = await walk(dir, { respectGitignore: false, followSymlinks: true });

    // The cycle guard must stop it; without one this never returns.
    assert.ok(outcome.files.length >= 1);
    assert.ok(outcome.files.length < 50, `cycle guard failed: ${outcome.files.length} files`);

    await fsp.rm(dir, { recursive: true, force: true });
  });

  it('honours .gitignore scoped to its own directory', async () => {
    const dir = await tempDir();
    await fsp.mkdir(path.join(dir, 'sub'));
    await fsp.writeFile(path.join(dir, 'sub', '.gitignore'), 'skipped.js\n');
    await fsp.writeFile(path.join(dir, 'sub', 'skipped.js'), 'const a = 1;');
    await fsp.writeFile(path.join(dir, 'sub', 'kept.js'), 'const a = 1;');
    await fsp.writeFile(path.join(dir, 'skipped.js'), 'const a = 1;');

    const outcome = await walk(dir, { respectGitignore: true });
    const names = outcome.files.map((f) => f.relativePath).sort();

    assert.ok(names.includes('sub/kept.js'));
    assert.ok(!names.includes('sub/skipped.js'), 'the nested .gitignore applies to its own dir');
    assert.ok(names.includes('skipped.js'), 'and must not leak upward');

    await fsp.rm(dir, { recursive: true, force: true });
  });

  it('skips files over the size limit and empty files', async () => {
    const dir = await tempDir();
    await fsp.writeFile(path.join(dir, 'big.js'), 'a'.repeat(5000));
    await fsp.writeFile(path.join(dir, 'empty.js'), '');
    await fsp.writeFile(path.join(dir, 'ok.js'), 'const a = 1;');

    const outcome = await walk(dir, { respectGitignore: false, maxFileSize: 1000 });
    assert.deepEqual(outcome.files.map((f) => f.relativePath), ['ok.js']);

    await fsp.rm(dir, { recursive: true, force: true });
  });

  it('accepts a single file as the target', async () => {
    const dir = await tempDir();
    const file = path.join(dir, 'a.js');
    await fsp.writeFile(file, 'const a = 1;');

    const outcome = await walk(file, {});
    assert.deepEqual(outcome.files.map((f) => f.relativePath), ['a.js']);

    await fsp.rm(dir, { recursive: true, force: true });
  });

  it('reports unreadable directories rather than throwing', async () => {
    const outcome = await walk(path.join(os.tmpdir(), 'trojan-does-not-exist-xyz')).catch(
      (error: Error) => error,
    );
    assert.ok(outcome instanceof Error, 'a missing root should reject, not hang');
  });
});

describe('binary detection', () => {
  it('treats a NUL byte as binary', () => {
    assert.equal(looksBinary(Buffer.from([0x41, 0x00, 0x42])), true);
    assert.equal(looksBinary(Buffer.from('plain text')), false);
  });

  it('recognises text candidates by extension and by name', () => {
    assert.equal(isTextCandidate('a.ts', '.ts'), true);
    assert.equal(isTextCandidate('Dockerfile', ''), true);
    assert.equal(isTextCandidate('.cursorrules', ''), true);
    assert.equal(isTextCandidate('image.png', '.png'), false);
    assert.equal(isTextCandidate('binary.exe', '.exe'), false);
  });
});
