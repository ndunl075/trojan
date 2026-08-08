/**
 * Prose extraction.
 *
 * The single biggest source of false positives in a tool like this is firing
 * on code. `system:` in a Kubernetes manifest is a field name; `system:` on
 * its own line in a docstring is a forged role marker. So before any rule
 * runs we work out which regions of a file an LLM would read as *language*
 * rather than as *code*: comments, docstrings, string literals, and whole
 * documents like markdown.
 *
 * This is a lexer, not a parser. It only needs to be right about where
 * comments and strings begin and end, which is tractable for every language
 * we care about in about 150 lines.
 */

import type { ProseSpan } from './types';

interface StringRule {
  open: string;
  close: string;
  /** May span newlines (template literals, docstrings, heredocs). */
  multiline: boolean;
  /** Backslash escapes apply inside. */
  escapable: boolean;
  /** Treat the contents as prose. Raw code strings usually are not worth it. */
  prose: boolean;
}

interface LanguageProfile {
  lineComments: string[];
  blockComments: [string, string][];
  strings: StringRule[];
  /** The entire file is prose (markdown, plain text, agent instruction files). */
  document?: boolean;
}

const DQ: StringRule = { open: '"', close: '"', multiline: false, escapable: true, prose: true };
const SQ: StringRule = { open: "'", close: "'", multiline: false, escapable: true, prose: true };
const BACKTICK: StringRule = {
  open: '`', close: '`', multiline: true, escapable: true, prose: true,
};
const PY_DOC_D: StringRule = {
  open: '"""', close: '"""', multiline: true, escapable: true, prose: true,
};
const PY_DOC_S: StringRule = {
  open: "'''", close: "'''", multiline: true, escapable: true, prose: true,
};

const C_LIKE: LanguageProfile = {
  lineComments: ['//'],
  blockComments: [['/*', '*/']],
  strings: [BACKTICK, DQ, SQ],
};

const HASH_LIKE: LanguageProfile = {
  lineComments: ['#'],
  blockComments: [],
  strings: [DQ, SQ],
};

const PYTHON: LanguageProfile = {
  lineComments: ['#'],
  blockComments: [],
  strings: [PY_DOC_D, PY_DOC_S, DQ, SQ],
};

const DOCUMENT: LanguageProfile = {
  lineComments: [],
  blockComments: [['<!--', '-->']],
  strings: [],
  document: true,
};

const MARKUP: LanguageProfile = {
  lineComments: [],
  blockComments: [['<!--', '-->']],
  strings: [DQ, SQ],
};

const JSON_LIKE: LanguageProfile = {
  lineComments: ['//'],
  blockComments: [['/*', '*/']],
  strings: [DQ],
};

const SQL_LIKE: LanguageProfile = {
  lineComments: ['--'],
  blockComments: [['/*', '*/']],
  strings: [SQ, DQ],
};

const LISP_LIKE: LanguageProfile = {
  lineComments: [';'],
  blockComments: [],
  strings: [DQ],
};

const PROFILES: Record<string, LanguageProfile> = {
  // Whole-file documents.
  '.md': DOCUMENT, '.mdx': DOCUMENT, '.markdown': DOCUMENT, '.txt': DOCUMENT,
  '.rst': DOCUMENT, '.adoc': DOCUMENT, '.asciidoc': DOCUMENT, '.org': DOCUMENT,
  '': DOCUMENT,

  // Markup.
  '.html': MARKUP, '.htm': MARKUP, '.xml': MARKUP, '.svg': MARKUP,
  '.vue': MARKUP, '.svelte': MARKUP, '.astro': MARKUP, '.plist': MARKUP,

  // Config.
  '.json': JSON_LIKE, '.jsonc': JSON_LIKE, '.json5': JSON_LIKE,
  '.ipynb': JSON_LIKE,
  '.yaml': HASH_LIKE, '.yml': HASH_LIKE, '.toml': HASH_LIKE,
  '.ini': { lineComments: ['#', ';'], blockComments: [], strings: [DQ, SQ] },
  '.cfg': HASH_LIKE, '.conf': HASH_LIKE, '.properties': HASH_LIKE,
  '.env': HASH_LIKE, '.editorconfig': HASH_LIKE,

  // JS family and friends.
  '.js': C_LIKE, '.jsx': C_LIKE, '.mjs': C_LIKE, '.cjs': C_LIKE,
  '.ts': C_LIKE, '.tsx': C_LIKE, '.mts': C_LIKE, '.cts': C_LIKE,
  '.java': C_LIKE, '.kt': C_LIKE, '.kts': C_LIKE, '.scala': C_LIKE,
  '.c': C_LIKE, '.h': C_LIKE, '.cc': C_LIKE, '.cpp': C_LIKE, '.hpp': C_LIKE,
  '.cxx': C_LIKE, '.hh': C_LIKE, '.m': C_LIKE, '.mm': C_LIKE,
  '.cs': C_LIKE, '.go': C_LIKE, '.rs': C_LIKE, '.swift': C_LIKE,
  '.php': { lineComments: ['//', '#'], blockComments: [['/*', '*/']], strings: [DQ, SQ] },
  '.dart': C_LIKE, '.zig': C_LIKE, '.sol': C_LIKE, '.v': C_LIKE,
  '.css': { lineComments: [], blockComments: [['/*', '*/']], strings: [DQ, SQ] },
  '.scss': C_LIKE, '.sass': C_LIKE, '.less': C_LIKE,
  '.proto': C_LIKE, '.graphql': HASH_LIKE, '.gql': HASH_LIKE,
  '.tf': HASH_LIKE, '.tfvars': HASH_LIKE, '.hcl': HASH_LIKE,

  // Hash-comment languages.
  '.py': PYTHON, '.pyi': PYTHON,
  '.rb': HASH_LIKE, '.pl': HASH_LIKE, '.pm': HASH_LIKE, '.r': HASH_LIKE,
  '.jl': HASH_LIKE, '.ex': HASH_LIKE, '.exs': HASH_LIKE, '.nim': HASH_LIKE,
  '.sh': HASH_LIKE, '.bash': HASH_LIKE, '.zsh': HASH_LIKE, '.fish': HASH_LIKE,
  '.mk': HASH_LIKE, '.cmake': HASH_LIKE, '.bzl': HASH_LIKE,
  '.dockerfile': HASH_LIKE,

  // Odd ones out.
  '.sql': SQL_LIKE,
  '.lua': { lineComments: ['--'], blockComments: [['--[[', ']]']], strings: [DQ, SQ] },
  '.hs': { lineComments: ['--'], blockComments: [['{-', '-}']], strings: [DQ] },
  '.elm': { lineComments: ['--'], blockComments: [['{-', '-}']], strings: [DQ] },
  '.erl': { lineComments: ['%'], blockComments: [], strings: [DQ] },
  '.hrl': { lineComments: ['%'], blockComments: [], strings: [DQ] },
  '.clj': LISP_LIKE, '.cljs': LISP_LIKE,
  '.ps1': { lineComments: ['#'], blockComments: [['<#', '#>']], strings: [DQ, SQ] },
  '.psm1': { lineComments: ['#'], blockComments: [['<#', '#>']], strings: [DQ, SQ] },
  '.bat': { lineComments: ['REM ', '::'], blockComments: [], strings: [DQ] },
  '.cmd': { lineComments: ['REM ', '::'], blockComments: [], strings: [DQ] },
  '.gradle': C_LIKE, '.sbt': C_LIKE, '.fs': C_LIKE,
};

const BASENAME_PROFILES: Record<string, LanguageProfile> = {
  Dockerfile: HASH_LIKE,
  Makefile: HASH_LIKE,
  Rakefile: HASH_LIKE,
  Gemfile: HASH_LIKE,
  Procfile: HASH_LIKE,
  Brewfile: HASH_LIKE,
  Jenkinsfile: C_LIKE,
  Vagrantfile: HASH_LIKE,
  CODEOWNERS: HASH_LIKE,
  '.gitignore': HASH_LIKE,
  '.gitattributes': HASH_LIKE,
  '.npmrc': HASH_LIKE,
  '.nvmrc': HASH_LIKE,
};

/**
 * Files a coding agent loads as instructions without being asked. Anything an
 * attacker plants here is read by the agent on the very first turn, so
 * findings inside them are treated as more serious.
 */
const AGENT_INSTRUCTION_FILES = new Set([
  'claude.md',
  'agents.md',
  'agent.md',
  '.cursorrules',
  '.windsurfrules',
  '.clinerules',
  '.roorules',
  '.aiderrules',
  'copilot-instructions.md',
  'gemini.md',
  'qwen.md',
  '.github/copilot-instructions.md',
  '.mcp.json',
  '.aider.conf.yml',
  'codex.md',
]);

export function isAgentInstructionFile(relativePath: string): boolean {
  const lower = relativePath.toLowerCase();
  const basename = lower.split('/').pop() ?? lower;
  if (AGENT_INSTRUCTION_FILES.has(basename)) return true;
  if (AGENT_INSTRUCTION_FILES.has(lower)) return true;
  // `.claude/` and `.cursor/` hold rules, commands, skills and hooks.
  if (/(^|\/)\.(claude|cursor|codex|windsurf|continue|cline|aider)\//.test(lower)) return true;
  if (/(^|\/)\.github\/(copilot|chatmodes|prompts|instructions)/.test(lower)) return true;
  return false;
}

export function profileFor(basename: string, ext: string): LanguageProfile {
  const byBasename = BASENAME_PROFILES[basename];
  if (byBasename) return byBasename;
  if (basename.startsWith('Dockerfile')) return HASH_LIKE;
  return PROFILES[ext] ?? DOCUMENT;
}

/**
 * Find every region of `text` that reads as prose.
 *
 * Adjacent spans of the same kind are merged so a block of consecutive `//`
 * lines becomes one span -- rules that look for multi-line instructions need
 * to see them as a unit.
 */
export function findProseSpans(text: string, basename: string, ext: string): ProseSpan[] {
  const profile = profileFor(basename, ext);

  if (profile.document) {
    return [{ start: 0, end: text.length, kind: 'document' }];
  }

  const spans: ProseSpan[] = [];
  const { lineComments, blockComments, strings } = profile;

  // Longest-first so `"""` wins over `"` and `/*` is not mistaken for `/`.
  const openers = [
    ...blockComments.map(([open, close]) => ({ token: open, close, kind: 'block' as const })),
    ...lineComments.map((token) => ({ token, close: '\n', kind: 'line' as const })),
    ...strings.map((rule) => ({ token: rule.open, close: rule.close, kind: 'string' as const, rule })),
  ].sort((a, b) => b.token.length - a.token.length);

  let i = 0;
  const length = text.length;

  outer: while (i < length) {
    for (const opener of openers) {
      if (!text.startsWith(opener.token, i)) continue;

      const contentStart = i + opener.token.length;

      if (opener.kind === 'line') {
        const newline = text.indexOf('\n', contentStart);
        const end = newline === -1 ? length : newline;
        push(spans, contentStart, end, 'comment');
        i = end;
        continue outer;
      }

      if (opener.kind === 'block') {
        const close = text.indexOf(opener.close, contentStart);
        const end = close === -1 ? length : close;
        push(spans, contentStart, end, 'comment');
        i = close === -1 ? length : close + opener.close.length;
        continue outer;
      }

      // String literal.
      const rule = (opener as { rule: StringRule }).rule;
      const end = findStringEnd(text, contentStart, rule);
      if (rule.prose && end.contentEnd > contentStart) {
        push(spans, contentStart, end.contentEnd, 'string');
      }
      i = end.next;
      continue outer;
    }

    i += 1;
  }

  return spans;
}

function findStringEnd(
  text: string,
  from: number,
  rule: StringRule,
): { contentEnd: number; next: number } {
  let i = from;
  while (i < text.length) {
    const ch = text[i] as string;

    if (rule.escapable && ch === '\\') {
      i += 2;
      continue;
    }
    if (!rule.multiline && ch === '\n') {
      // Unterminated single-line string: bail at the newline rather than
      // swallowing the rest of the file.
      return { contentEnd: i, next: i };
    }
    if (text.startsWith(rule.close, i)) {
      return { contentEnd: i, next: i + rule.close.length };
    }
    i += 1;
  }
  return { contentEnd: text.length, next: text.length };
}

function push(spans: ProseSpan[], start: number, end: number, kind: ProseSpan['kind']): void {
  if (end <= start) return;
  const last = spans[spans.length - 1];
  // Merge runs like consecutive `//` lines separated only by whitespace.
  if (last && last.kind === kind && start - last.end <= 2) {
    last.end = end;
    return;
  }
  spans.push({ start, end, kind });
}

/** Binary search over the sorted, non-overlapping span list. */
export function makeProseLookup(spans: ProseSpan[]): (index: number) => boolean {
  if (spans.length === 0) return () => false;
  if (spans.length === 1 && spans[0]!.kind === 'document') return () => true;

  return (index: number): boolean => {
    let low = 0;
    let high = spans.length - 1;
    while (low <= high) {
      const mid = (low + high) >> 1;
      const span = spans[mid] as ProseSpan;
      if (index < span.start) high = mid - 1;
      else if (index >= span.end) low = mid + 1;
      else return true;
    }
    return false;
  };
}
