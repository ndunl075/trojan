/**
 * The scan pipeline: discover files, build a context per file, run the rules,
 * then post-process the raw findings into something worth showing a person.
 *
 * Two post-processing passes carry most of the signal:
 *
 *   Correlation. One suspicious phrase is noise. A README that trips an
 *   instruction override *and* a forged role marker *and* a trust assertion is
 *   not a coincidence, so severity is raised once a file trips three distinct
 *   rule families.
 *
 *   Agent-file weighting. The same finding matters more in CLAUDE.md than in
 *   a test fixture, because the agent reads CLAUDE.md before you ask it
 *   anything.
 */

import * as fsp from 'node:fs/promises';
import * as path from 'node:path';

import { AllowList, Baseline, isInlineIgnored, parseInlineIgnores } from './baseline';
import {
  findProseSpans,
  isAgentInstructionFile,
  makeProseLookup,
  normalizeComments,
} from './prose';
import { selectRules, type RuleSelection } from './rules';
import {
  bumpSeverity,
  severityRank,
  type FileContext,
  type Finding,
  type RawFinding,
  type Rule,
  type ScanResult,
  type Severity,
} from './types';
import { fingerprint, LineIndex, truncate, visualize } from './util/text';
import { looksBinary, toPosix, walk, type WalkOptions } from './walker';

export interface ScanOptions extends WalkOptions {
  /** Findings below this severity are dropped from the result. */
  minSeverity?: Severity;
  rules?: RuleSelection;
  baseline?: Baseline;
  allow?: AllowList;
  /** Report baselined findings instead of suppressing them. */
  showSuppressed?: boolean;
  /** Stop after this many findings. 0 means no limit. */
  maxFindings?: number;
  /** Files read at once. Higher is not always faster; 16 saturates most disks. */
  concurrency?: number;
  /** Skip the correlation and agent-file severity boosts. */
  noBoost?: boolean;
}

const SNIPPET_LIMIT = 160;
const CONTEXT_LIMIT = 200;
/** How many distinct rule families a file must trip before severity is raised. */
const CORRELATION_THRESHOLD = 3;

export async function scan(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  const started = Date.now();
  const root = path.resolve(target);
  const rules = selectRules(options.rules);
  const baseline = options.baseline ?? Baseline.empty();
  const allow = options.allow ?? new AllowList();
  const minRank = severityRank(options.minSeverity ?? 'info');
  const concurrency = Math.max(1, options.concurrency ?? 16);

  const outcome = await walk(root, options);
  const errors = [...outcome.errors];
  const findings: Finding[] = [];
  const suppressed: Finding[] = [];
  let bytesScanned = 0;
  let filesScanned = 0;
  let filesSkipped = outcome.skipped;

  // A simple index-sharing pool. Files are independent, so this is all the
  // coordination the scan needs.
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, outcome.files.length) }, async () => {
    for (;;) {
      const next = cursor;
      cursor += 1;
      const file = outcome.files[next];
      if (!file) return;

      let buffer: Buffer;
      try {
        buffer = await fsp.readFile(file.absolutePath);
      } catch (error) {
        errors.push({
          file: file.relativePath,
          message: error instanceof Error ? error.message : String(error),
        });
        continue;
      }

      if (looksBinary(buffer)) {
        filesSkipped += 1;
        continue;
      }

      filesScanned += 1;
      bytesScanned += buffer.length;

      const fileFindings = scanText(buffer.toString('utf8'), file.relativePath, file.absolutePath, {
        rules,
        baseline,
        allow,
        minRank,
        noBoost: options.noBoost ?? false,
        suppressedOut: suppressed,
      });
      findings.push(...fileFindings);
    }
  });

  await Promise.all(workers);

  findings.sort(compareFindings);
  suppressed.sort(compareFindings);

  const limited =
    options.maxFindings && options.maxFindings > 0
      ? findings.slice(0, options.maxFindings)
      : findings;

  return {
    root,
    findings: limited,
    suppressed: options.showSuppressed ? suppressed : [],
    stats: {
      filesScanned,
      filesSkipped,
      bytesScanned,
      durationMs: Date.now() - started,
    },
    errors,
  };
}

interface ScanTextContext {
  rules: Rule[];
  baseline: Baseline;
  allow: AllowList;
  minRank: number;
  noBoost: boolean;
  suppressedOut: Finding[];
}

/**
 * Scan one file's text. Exported because it is the whole tool minus the
 * filesystem, which makes it the natural unit to test and to embed.
 */
export function scanText(
  text: string,
  relativePath: string,
  absolutePath: string,
  options: ScanTextContext,
): Finding[] {
  const basename = path.basename(relativePath);
  const ext = path.extname(basename).toLowerCase();
  const posixPath = toPosix(relativePath);

  const prose = findProseSpans(text, basename, ext);
  const lookup = makeProseLookup(prose);
  const isDocument = prose.length === 1 && prose[0]?.kind === 'document';

  // Rules see a version with continuation markers blanked out, so a phrase
  // split across several `//` lines still matches. The substitution preserves
  // length, so every offset a rule reports still indexes the original text.
  const ruleText = normalizeComments(text, prose);

  const ctx: FileContext = {
    path: posixPath,
    absolutePath,
    ext,
    basename,
    text: ruleText,
    prose,
    isDocument,
    isAgentInstructionFile: isAgentInstructionFile(posixPath),
    inProse: lookup,
  };

  const raw: { rule: Rule; finding: RawFinding }[] = [];
  for (const rule of options.rules) {
    let produced: RawFinding[];
    try {
      produced = rule.scan(ctx);
    } catch {
      // A rule throwing must never take the scan down with it. Skipping one
      // detector is a far better outcome than reporting nothing at all.
      continue;
    }
    for (const finding of produced) raw.push({ rule, finding });
  }

  if (raw.length === 0) return [];

  // Correlation is computed per file, before thresholds are applied, so a
  // low-severity finding can still contribute to the case against a file.
  const families = new Set(raw.map(({ rule }) => rule.family));
  const corroborated = !options.noBoost && families.size >= CORRELATION_THRESHOLD;
  const agentFile = !options.noBoost && ctx.isAgentInstructionFile;

  const lineIndex = new LineIndex(text);
  const inlineIgnores = parseInlineIgnores(text);
  const kept: Finding[] = [];

  for (const { rule, finding } of raw) {
    const { line, column } = lineIndex.locate(finding.index);
    const baseSeverity = finding.severity ?? rule.severity;

    let severity = baseSeverity;
    let boostedBy: string | undefined;

    // agent-config findings are informational by design; boosting them would
    // just mean every repo with a CLAUDE.md reports a medium.
    if (rule.family !== 'agent-config') {
      if (corroborated) {
        severity = bumpSeverity(severity);
        boostedBy = `${families.size} distinct injection techniques in this file`;
      }
      if (agentFile) {
        severity = bumpSeverity(severity);
        boostedBy = boostedBy
          ? `${boostedBy}; file is auto-loaded as agent instructions`
          : 'file is auto-loaded as agent instructions';
      }
    }

    const snippet = truncate(visualize(finding.match), SNIPPET_LIMIT);
    const context = truncate(visualize(lineIndex.lineAt(finding.index).trim()), CONTEXT_LIMIT);

    const resolved: Finding = {
      ruleId: rule.id,
      ruleTitle: rule.title,
      family: rule.family,
      severity,
      baseSeverity,
      file: posixPath,
      line,
      column,
      snippet,
      context,
      message: finding.message ?? rule.message,
      fingerprint: fingerprint(rule.id, posixPath, finding.match),
    };
    if (boostedBy) resolved.boostedBy = boostedBy;
    if (finding.detail) resolved.detail = finding.detail;

    if (
      options.baseline.has(resolved.fingerprint) ||
      isInlineIgnored(inlineIgnores, line, rule.id) ||
      options.allow.allows(resolved)
    ) {
      options.suppressedOut.push(resolved);
      continue;
    }

    if (severityRank(severity) < options.minRank) continue;

    kept.push(resolved);
  }

  return kept;
}

function compareFindings(a: Finding, b: Finding): number {
  const bySeverity = severityRank(b.severity) - severityRank(a.severity);
  if (bySeverity !== 0) return bySeverity;
  const byFile = a.file.localeCompare(b.file);
  if (byFile !== 0) return byFile;
  if (a.line !== b.line) return a.line - b.line;
  return a.column - b.column;
}
