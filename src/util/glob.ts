/**
 * A small gitignore-flavoured glob matcher.
 *
 * We deliberately do not pull in `minimatch` or `ignore`. The tool has to be
 * cheap enough to run on every commit, and this is roughly 100 lines of regex
 * translation that covers everything a .gitignore or an `--exclude` flag
 * realistically uses: `*`, `**`, `?`, character classes, `!` negation,
 * anchoring and directory-only patterns.
 */

export interface GlobPattern {
  /** The source text, kept for error messages. */
  source: string;
  negated: boolean;
  /** Only matches directories (pattern ended in `/`). */
  directoryOnly: boolean;
  /** Matches the path itself or anything beneath it. */
  regex: RegExp;
  /** Matches only things strictly *beneath* the path. */
  descendantRegex: RegExp;
}

/** Translate one gitignore-style line into a regex. Returns null for comments. */
export function compilePattern(raw: string): GlobPattern | null {
  let pattern = raw;

  // Strip a trailing comment-free whitespace run, but honour an escaped space.
  pattern = pattern.replace(/(?<!\\)\s+$/, '');
  if (pattern === '' || pattern.startsWith('#')) return null;

  let negated = false;
  if (pattern.startsWith('!')) {
    negated = true;
    pattern = pattern.slice(1);
  } else if (pattern.startsWith('\\!')) {
    pattern = pattern.slice(1);
  }

  let directoryOnly = false;
  if (pattern.endsWith('/')) {
    directoryOnly = true;
    pattern = pattern.slice(0, -1);
  }

  // A pattern with a slash anywhere but the end is anchored to the ignore
  // file's directory. Otherwise it matches at any depth.
  const anchored = pattern.includes('/');
  if (pattern.startsWith('/')) pattern = pattern.slice(1);

  const body = globToRegexSource(pattern);
  const prefix = anchored ? '^' : '^(?:.*/)?';
  // Matching a directory implicitly matches everything under it.
  const regex = new RegExp(`${prefix}${body}(?:/.*)?$`);
  const descendantRegex = new RegExp(`${prefix}${body}/.+$`);

  return { source: raw, negated, directoryOnly, regex, descendantRegex };
}

function globToRegexSource(pattern: string): string {
  let out = '';
  let i = 0;

  while (i < pattern.length) {
    const ch = pattern[i] as string;

    if (ch === '\\') {
      const next = pattern[i + 1];
      if (next !== undefined) {
        out += escapeLiteral(next);
        i += 2;
        continue;
      }
      out += '\\\\';
      i += 1;
      continue;
    }

    if (ch === '*') {
      const isDoubleStar = pattern[i + 1] === '*';
      if (isDoubleStar) {
        const before = pattern[i - 1];
        const after = pattern[i + 2];
        const atSegmentStart = before === undefined || before === '/';
        const atSegmentEnd = after === undefined || after === '/';

        if (atSegmentStart && atSegmentEnd) {
          if (after === '/') {
            // `**/` may match zero directories, so swallow the slash too.
            out += '(?:.*/)?';
            i += 3;
            continue;
          }
          out += '.*';
          i += 2;
          continue;
        }
        // A `**` glued to other characters degrades to `*`, same as git.
        out += '[^/]*';
        i += 2;
        continue;
      }
      out += '[^/]*';
      i += 1;
      continue;
    }

    if (ch === '?') {
      out += '[^/]';
      i += 1;
      continue;
    }

    if (ch === '[') {
      const close = findClassEnd(pattern, i);
      if (close === -1) {
        out += '\\[';
        i += 1;
        continue;
      }
      let cls = pattern.slice(i + 1, close);
      // gitignore accepts `!` as the negation marker inside a class.
      if (cls.startsWith('!')) cls = `^${cls.slice(1)}`;
      out += `[${cls.replace(/\\/g, '\\\\')}]`;
      i = close + 1;
      continue;
    }

    out += escapeLiteral(ch);
    i += 1;
  }

  return out;
}

function findClassEnd(pattern: string, openIndex: number): number {
  let i = openIndex + 1;
  if (pattern[i] === '!' || pattern[i] === '^') i += 1;
  if (pattern[i] === ']') i += 1; // A leading `]` is a literal.
  while (i < pattern.length) {
    if (pattern[i] === ']') return i;
    i += 1;
  }
  return -1;
}

function escapeLiteral(ch: string): string {
  return /[.*+?^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
}

/**
 * An ordered set of patterns evaluated gitignore-style: the last pattern that
 * matches decides, so a later `!foo` re-includes something an earlier rule
 * excluded.
 */
export class PatternSet {
  private readonly patterns: GlobPattern[] = [];

  constructor(lines: Iterable<string> = []) {
    this.add(lines);
  }

  add(lines: Iterable<string>): this {
    for (const line of lines) {
      const compiled = compilePattern(line);
      if (compiled) this.patterns.push(compiled);
    }
    return this;
  }

  get size(): number {
    return this.patterns.length;
  }

  /**
   * @param path      Path relative to the set's base, forward slashes, no leading slash.
   * @param isDirectory Whether `path` refers to a directory.
   * @returns true when the path is excluded by this set.
   */
  matches(path: string, isDirectory = false): boolean {
    let excluded = false;
    for (const pattern of this.patterns) {
      // `build/` never matches the file `build`, but it does match everything
      // nested under a directory called `build`.
      const regex =
        pattern.directoryOnly && !isDirectory ? pattern.descendantRegex : pattern.regex;
      if (!regex.test(path)) continue;
      excluded = !pattern.negated;
    }
    return excluded;
  }
}
