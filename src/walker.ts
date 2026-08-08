/**
 * Filesystem discovery.
 *
 * The walker's job is to hand the scanner a stream of files that are (a) text,
 * (b) small enough to be worth reading and (c) not obviously vendored. Getting
 * this right is most of the tool's performance story: skipping node_modules
 * and binaries is what keeps a full scan in the tens of milliseconds.
 */

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';

import { PatternSet } from './util/glob';

/** Directories that are never worth scanning and are expensive to walk. */
export const DEFAULT_EXCLUDES = [
  '.git/',
  '.hg/',
  '.svn/',
  'node_modules/',
  'bower_components/',
  'vendor/',
  'dist/',
  'build/',
  'out/',
  'target/',
  '.next/',
  '.nuxt/',
  '.svelte-kit/',
  '.turbo/',
  '.parcel-cache/',
  '.cache/',
  '__pycache__/',
  '.venv/',
  'venv/',
  '.tox/',
  '.mypy_cache/',
  '.pytest_cache/',
  '.gradle/',
  '.idea/',
  'Pods/',
  'coverage/',
  '.nyc_output/',
  '*.min.js',
  '*.min.css',
  '*.map',
  '*.lock',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'Cargo.lock',
  'poetry.lock',
  'composer.lock',
  'go.sum',
];

/**
 * Extensions we read. An allowlist beats a binary-extension denylist here:
 * new binary formats appear constantly, new text formats rarely do.
 */
export const TEXT_EXTENSIONS = new Set([
  // Docs and prose -- where injections live most often.
  '.md', '.mdx', '.markdown', '.rst', '.txt', '.adoc', '.asciidoc', '.org',
  // Config.
  '.json', '.jsonc', '.json5', '.yaml', '.yml', '.toml', '.ini', '.cfg',
  '.conf', '.properties', '.env', '.editorconfig', '.xml', '.plist',
  // JavaScript family.
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts', '.vue',
  '.svelte', '.astro',
  // Everything else people actually ship.
  '.py', '.pyi', '.rb', '.go', '.rs', '.java', '.kt', '.kts', '.scala',
  '.c', '.h', '.cc', '.cpp', '.hpp', '.cxx', '.hh', '.m', '.mm',
  '.cs', '.fs', '.swift', '.php', '.pl', '.pm', '.lua', '.r', '.jl',
  '.dart', '.ex', '.exs', '.erl', '.hrl', '.clj', '.cljs', '.hs', '.elm',
  '.zig', '.nim', '.v', '.sol',
  // Shells and build.
  '.sh', '.bash', '.zsh', '.fish', '.ps1', '.psm1', '.bat', '.cmd',
  '.mk', '.cmake', '.gradle', '.sbt', '.bzl',
  // Web.
  '.html', '.htm', '.css', '.scss', '.sass', '.less', '.graphql', '.gql',
  '.sql', '.proto', '.tf', '.tfvars', '.hcl', '.dockerfile', '.ipynb',
]);

/** Extensionless files that are still text and still worth reading. */
export const TEXT_FILENAMES = new Set([
  'Dockerfile', 'Makefile', 'Rakefile', 'Gemfile', 'Procfile', 'Brewfile',
  'Jenkinsfile', 'Vagrantfile', 'CODEOWNERS', 'LICENSE', 'NOTICE', 'README',
  'CHANGELOG', 'AUTHORS', 'CONTRIBUTING', 'AGENTS', 'AGENTS.md',
  '.gitignore', '.gitattributes', '.npmrc', '.nvmrc', '.babelrc',
  '.eslintrc', '.prettierrc', '.cursorrules', '.windsurfrules', '.clinerules',
  '.aiderignore', '.trojanignore',
]);

export interface WalkOptions {
  /** Extra exclude patterns from config or `--exclude`. */
  exclude?: string[];
  /** When set, only files matching one of these patterns are scanned. */
  include?: string[];
  /** Skip the built-in exclude list. Rarely what you want. */
  noDefaultExcludes?: boolean;
  /** Honour .gitignore files found along the way. Default true. */
  respectGitignore?: boolean;
  /** Skip files larger than this many bytes. Default 2 MiB. */
  maxFileSize?: number;
  /** Follow symlinks. Default false -- symlink loops are a real hazard. */
  followSymlinks?: boolean;
}

export interface DiscoveredFile {
  absolutePath: string;
  /** Forward-slashed path relative to the scan root. */
  relativePath: string;
  size: number;
}

export interface WalkOutcome {
  files: DiscoveredFile[];
  skipped: number;
  errors: { file: string; message: string }[];
}

const DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024;

/** Normalise a filesystem path to the forward-slashed form rules and reports use. */
export function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

/**
 * Heuristic binary check: a NUL byte in the first 8 KiB. This is what git
 * itself does, and it is far cheaper and more reliable than sniffing magic
 * numbers for every format under the sun.
 */
export function looksBinary(buffer: Buffer): boolean {
  const limit = Math.min(buffer.length, 8192);
  for (let i = 0; i < limit; i += 1) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

export function isTextCandidate(basename: string, ext: string): boolean {
  if (TEXT_EXTENSIONS.has(ext)) return true;
  if (TEXT_FILENAMES.has(basename)) return true;
  // Dotted variants like `.eslintrc.yaml` or `Dockerfile.prod`.
  const stem = basename.split('.')[0] as string;
  if (stem !== '' && TEXT_FILENAMES.has(stem)) return true;
  if (basename.startsWith('.') && !ext) return true;
  return false;
}

/**
 * Walk `root` and collect scannable files.
 *
 * Gitignore handling is scoped the way git scopes it: a .gitignore applies to
 * its own directory and below, so we carry a stack of pattern sets down the
 * tree rather than flattening everything into one global list.
 */
export async function walk(root: string, options: WalkOptions = {}): Promise<WalkOutcome> {
  const {
    exclude = [],
    include = [],
    noDefaultExcludes = false,
    respectGitignore = true,
    maxFileSize = DEFAULT_MAX_FILE_SIZE,
    followSymlinks = false,
  } = options;

  const files: DiscoveredFile[] = [];
  const errors: { file: string; message: string }[] = [];
  let skipped = 0;

  const rootStat = await fsp.stat(root);

  // Scanning a single file directly is a legitimate mode -- it is how the
  // pre-commit hook passes staged paths.
  if (rootStat.isFile()) {
    const basename = path.basename(root);
    return {
      files: [{ absolutePath: root, relativePath: basename, size: rootStat.size }],
      skipped: 0,
      errors: [],
    };
  }

  const baseExcludes = new PatternSet(noDefaultExcludes ? [] : DEFAULT_EXCLUDES).add(exclude);
  const includeSet = include.length > 0 ? new PatternSet(include) : null;
  const seenRealPaths = new Set<string>();

  interface Frame {
    dir: string;
    relative: string;
    /** Gitignore sets inherited from ancestors, each with its own base path. */
    ignores: { base: string; set: PatternSet }[];
  }

  const stack: Frame[] = [{ dir: root, relative: '', ignores: [] }];

  while (stack.length > 0) {
    const frame = stack.pop() as Frame;
    let entries: fs.Dirent[];

    try {
      entries = await fsp.readdir(frame.dir, { withFileTypes: true });
    } catch (error) {
      errors.push({ file: toPosix(frame.relative || '.'), message: describe(error) });
      continue;
    }

    let ignores = frame.ignores;
    if (respectGitignore) {
      const local = await readIgnoreFile(frame.dir);
      if (local) ignores = [...ignores, { base: frame.relative, set: local }];
    }

    for (const entry of entries) {
      const absolutePath = path.join(frame.dir, entry.name);
      const relativePath = frame.relative ? `${frame.relative}/${entry.name}` : entry.name;

      let isDirectory = entry.isDirectory();
      let isFile = entry.isFile();

      if (entry.isSymbolicLink()) {
        if (!followSymlinks) continue;
        try {
          const target = await fsp.stat(absolutePath);
          isDirectory = target.isDirectory();
          isFile = target.isFile();
        } catch {
          continue; // Broken symlink.
        }
      }

      if (!isDirectory && !isFile) continue;

      if (baseExcludes.matches(relativePath, isDirectory)) {
        skipped += 1;
        continue;
      }
      if (isIgnored(ignores, relativePath, isDirectory)) {
        skipped += 1;
        continue;
      }

      if (isDirectory) {
        if (followSymlinks) {
          // Cheap cycle guard; only needed once we are chasing links.
          try {
            const real = await fsp.realpath(absolutePath);
            if (seenRealPaths.has(real)) continue;
            seenRealPaths.add(real);
          } catch {
            continue;
          }
        }
        stack.push({ dir: absolutePath, relative: relativePath, ignores });
        continue;
      }

      const ext = path.extname(entry.name).toLowerCase();
      if (!isTextCandidate(entry.name, ext)) {
        skipped += 1;
        continue;
      }
      if (includeSet && !includeSet.matches(relativePath, false)) {
        skipped += 1;
        continue;
      }

      let size: number;
      try {
        size = (await fsp.stat(absolutePath)).size;
      } catch (error) {
        errors.push({ file: relativePath, message: describe(error) });
        continue;
      }

      if (size > maxFileSize || size === 0) {
        skipped += 1;
        continue;
      }

      files.push({ absolutePath, relativePath, size });
    }
  }

  files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  return { files, skipped, errors };
}

function isIgnored(
  ignores: { base: string; set: PatternSet }[],
  relativePath: string,
  isDirectory: boolean,
): boolean {
  for (const { base, set } of ignores) {
    const scoped = base === '' ? relativePath : relativePath.slice(base.length + 1);
    if (set.matches(scoped, isDirectory)) return true;
  }
  return false;
}

async function readIgnoreFile(dir: string): Promise<PatternSet | null> {
  const sets: string[] = [];
  for (const name of ['.gitignore', '.trojanignore']) {
    try {
      const text = await fsp.readFile(path.join(dir, name), 'utf8');
      sets.push(text);
    } catch {
      // Absent is the common case; nothing to do.
    }
  }
  if (sets.length === 0) return null;
  return new PatternSet(sets.join('\n').split(/\r?\n/));
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
