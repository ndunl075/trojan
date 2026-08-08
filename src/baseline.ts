/**
 * Baselining and suppression.
 *
 * A scanner that cannot be told "yes, I know" gets turned off. Three
 * mechanisms, borrowed from how secret scanners handle the same problem:
 *
 *   1. A baseline file recording accepted findings by fingerprint. Adopt the
 *      tool on an existing repo, accept what is there, and only new findings
 *      break the build.
 *   2. Inline `trojan-ignore` comments, for the single line that will always
 *      look suspicious.
 *   3. Config-level allow patterns, for a phrase that is genuinely part of the
 *      project's vocabulary.
 *
 * Fingerprints are rule + path + normalised snippet, so reformatting a file or
 * inserting lines above a finding does not silently un-accept it.
 */

import * as fsp from 'node:fs/promises';

import type { Finding } from './types';

export const BASELINE_FILENAME = 'trojan-baseline.json';
export const BASELINE_VERSION = 1;

export interface BaselineEntry {
  rule: string;
  file: string;
  line: number;
  snippet: string;
  /** Free text for whoever accepted it. */
  note?: string;
}

export interface BaselineFile {
  version: number;
  generatedAt: string;
  /** Keyed by fingerprint. */
  findings: Record<string, BaselineEntry>;
}

export class Baseline {
  constructor(private readonly entries: Map<string, BaselineEntry> = new Map()) {}

  static empty(): Baseline {
    return new Baseline();
  }

  static fromFindings(findings: Finding[], note?: string): Baseline {
    const entries = new Map<string, BaselineEntry>();
    for (const finding of findings) {
      const entry: BaselineEntry = {
        rule: finding.ruleId,
        file: finding.file,
        line: finding.line,
        snippet: finding.snippet.slice(0, 200),
      };
      if (note) entry.note = note;
      entries.set(finding.fingerprint, entry);
    }
    return new Baseline(entries);
  }

  static async load(path: string): Promise<Baseline> {
    const raw = await fsp.readFile(path, 'utf8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(
        `Baseline file ${path} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    const data = parsed as Partial<BaselineFile>;
    if (typeof data !== 'object' || data === null || typeof data.findings !== 'object') {
      throw new Error(`Baseline file ${path} is missing a "findings" object.`);
    }
    if (data.version !== undefined && data.version > BASELINE_VERSION) {
      throw new Error(
        `Baseline file ${path} was written by a newer version of trojan (format ${data.version}, this build understands ${BASELINE_VERSION}).`,
      );
    }

    return new Baseline(new Map(Object.entries(data.findings as Record<string, BaselineEntry>)));
  }

  /** Load if the file exists, otherwise an empty baseline. */
  static async loadIfPresent(path: string): Promise<Baseline> {
    try {
      await fsp.access(path);
    } catch {
      return Baseline.empty();
    }
    return Baseline.load(path);
  }

  get size(): number {
    return this.entries.size;
  }

  has(fingerprint: string): boolean {
    return this.entries.has(fingerprint);
  }

  toJSON(): BaselineFile {
    return {
      version: BASELINE_VERSION,
      generatedAt: new Date().toISOString(),
      findings: Object.fromEntries([...this.entries.entries()].sort(([a], [b]) => a.localeCompare(b))),
    };
  }

  async write(path: string): Promise<void> {
    await fsp.writeFile(path, `${JSON.stringify(this.toJSON(), null, 2)}\n`, 'utf8');
  }
}

/**
 * Inline suppression, checked on the finding's own line and the line above.
 *
 * Supported forms, in any comment syntax:
 *   trojan-ignore
 *   trojan-ignore-next-line
 *   trojan-ignore unicode/homoglyph, injection/tool-abuse
 */
const IGNORE_RE = /trojan-ignore(-next-line)?(?:\s*[: ]\s*([A-Za-z0-9/_,\s-]+))?/;

export interface InlineIgnore {
  /** Rule ids this comment covers. Empty means every rule. */
  rules: Set<string>;
}

/** Parse every inline ignore in a file, keyed by the line number it applies to. */
export function parseInlineIgnores(text: string): Map<number, InlineIgnore> {
  const applies = new Map<number, InlineIgnore>();
  const lines = text.split('\n');

  for (let i = 0; i < lines.length; i += 1) {
    const match = IGNORE_RE.exec(lines[i] as string);
    if (!match) continue;

    const isNextLine = match[1] !== undefined;
    const ruleList = (match[2] ?? '')
      .split(/[,\s]+/)
      .map((id) => id.trim())
      .filter((id) => id.includes('/'));

    // 1-based: `-next-line` targets i+2, a bare comment targets its own line.
    const target = isNextLine ? i + 2 : i + 1;
    const existing = applies.get(target);
    if (existing) {
      for (const id of ruleList) existing.rules.add(id);
      // A bare ignore on the same line wins over a scoped one.
      if (ruleList.length === 0) existing.rules.clear();
    } else {
      applies.set(target, { rules: new Set(ruleList) });
    }
  }

  return applies;
}

export function isInlineIgnored(
  ignores: Map<number, InlineIgnore>,
  line: number,
  ruleId: string,
): boolean {
  const entry = ignores.get(line);
  if (!entry) return false;
  return entry.rules.size === 0 || entry.rules.has(ruleId);
}

/**
 * Project-level allowances: a finding whose snippet or containing line matches
 * one of these is dropped. Useful when a phrase is part of the domain, e.g. a
 * repo that legitimately documents prompt-injection payloads.
 */
export class AllowList {
  private readonly patterns: RegExp[];

  constructor(sources: string[] = []) {
    this.patterns = sources.map((source) => {
      try {
        return new RegExp(source, 'i');
      } catch (error) {
        throw new Error(
          `Invalid allow pattern ${JSON.stringify(source)}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    });
  }

  get size(): number {
    return this.patterns.length;
  }

  allows(finding: Finding): boolean {
    if (this.patterns.length === 0) return false;
    return this.patterns.some(
      (pattern) => pattern.test(finding.snippet) || pattern.test(finding.context),
    );
  }
}
