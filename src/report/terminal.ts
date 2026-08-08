/**
 * Human-readable output.
 *
 * The design goal is that someone who has never used this tool can read the
 * output once and know whether to worry. That means every finding answers
 * three questions in order: where is it, what is it, and why does it matter.
 * The "why" is prose, not a rule id.
 */

import { Painter } from '../util/color';
import { SEVERITIES, severityRank, type Finding, type ScanResult, type Severity } from '../types';

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

const SEVERITY_ICON: Record<Severity, string> = {
  critical: '!!',
  high: '!',
  medium: '~',
  low: '-',
  info: 'i',
};

export interface TerminalOptions {
  painter: Painter;
  /** Drop the per-finding detail and print one line each. */
  compact?: boolean;
  /** Suppress the header and the timing footer. */
  quiet?: boolean;
  /** Root directory, used to make the header meaningful. */
  showSuppressedCount?: number;
}

function colorFor(painter: Painter, severity: Severity, text: string): string {
  switch (severity) {
    case 'critical':
      return painter.paint(text, 'brightRed', 'bold');
    case 'high':
      return painter.paint(text, 'red');
    case 'medium':
      return painter.paint(text, 'yellow');
    case 'low':
      return painter.paint(text, 'blue');
    case 'info':
      return painter.gray(text);
  }
}

export function formatTerminal(result: ScanResult, options: TerminalOptions): string {
  const { painter } = options;
  const lines: string[] = [];

  if (!options.quiet) {
    lines.push('');
    lines.push(
      `${painter.paint('trojan', 'magenta', 'bold')} ${painter.dim('scanning for prompt injections aimed at AI coding agents')}`,
    );
    lines.push(painter.dim(`  ${result.root}`));
    lines.push('');
  }

  if (result.findings.length === 0) {
    lines.push(
      `${painter.green('  No prompt injection indicators found.')} ${painter.dim(
        `(${result.stats.filesScanned} files)`,
      )}`,
    );
    lines.push(...footer(result, options));
    return `${lines.join('\n')}\n`;
  }

  // Grouped by severity, then by file, so the reader triages top-down and
  // never has to hold two files in their head at once.
  for (const severity of [...SEVERITIES].reverse()) {
    const inBucket = result.findings.filter((f) => f.severity === severity);
    if (inBucket.length === 0) continue;

    const label = colorFor(painter, severity, `${SEVERITY_LABEL[severity]}`);
    lines.push(`${label} ${painter.dim(`(${inBucket.length})`)}`);
    lines.push('');

    for (const [file, findings] of groupByFile(inBucket)) {
      lines.push(`  ${painter.paint(file, 'cyan', 'underline')}`);
      for (const finding of findings) {
        lines.push(...renderFinding(finding, painter, options.compact ?? false));
      }
      lines.push('');
    }
  }

  lines.push(...summary(result, painter));
  lines.push(...footer(result, options));

  return `${lines.join('\n')}\n`;
}

function renderFinding(finding: Finding, painter: Painter, compact: boolean): string[] {
  const location = painter.dim(`${finding.line}:${finding.column}`);
  const icon = colorFor(painter, finding.severity, SEVERITY_ICON[finding.severity]);
  const title = painter.bold(finding.ruleTitle);

  if (compact) {
    return [`    ${icon} ${location} ${title} ${painter.dim(finding.ruleId)}`];
  }

  const out: string[] = [];
  out.push(`    ${icon} ${location}  ${title}  ${painter.dim(finding.ruleId)}`);
  out.push(`       ${painter.dim('>')} ${painter.yellow(finding.context || finding.snippet)}`);
  out.push(`       ${wrap(finding.message, 72, '         ')}`);

  if (finding.boostedBy) {
    out.push(
      `       ${painter.magenta('^')} ${painter.dim(
        `raised from ${finding.baseSeverity} - ${finding.boostedBy}`,
      )}`,
    );
  }

  return out;
}

function summary(result: ScanResult, painter: Painter): string[] {
  const counts = new Map<Severity, number>();
  for (const finding of result.findings) {
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  }

  const parts = [...SEVERITIES]
    .reverse()
    .filter((severity) => counts.has(severity))
    .map((severity) => colorFor(painter, severity, `${counts.get(severity)} ${severity}`));

  return [`  ${painter.bold(`${result.findings.length} finding${result.findings.length === 1 ? '' : 's'}`)}: ${parts.join(painter.dim(', '))}`];
}

function footer(result: ScanResult, options: TerminalOptions): string[] {
  const { painter } = options;
  const out: string[] = [];

  if (!options.quiet) {
    const suppressed = options.showSuppressedCount ?? 0;
    const suppressedNote = suppressed > 0 ? `, ${suppressed} suppressed` : '';

    out.push(
      painter.dim(
        `  ${result.stats.filesScanned} files scanned, ${result.stats.filesSkipped} skipped${suppressedNote} in ${result.stats.durationMs}ms`,
      ),
    );
  }

  // Errors print even in quiet mode. Every one of them means some part of the
  // repository went unchecked, and a security tool that hides reduced coverage
  // is worse than one that reports nothing at all.
  if (result.errors.length > 0) {
    out.push(
      painter.yellow(
        `  ${result.errors.length} file(s) were not fully scanned:`,
      ),
    );
    for (const error of result.errors.slice(0, 5)) {
      out.push(painter.dim(`    ${error.file}: ${error.message}`));
    }
    if (result.errors.length > 5) {
      out.push(painter.dim(`    ...and ${result.errors.length - 5} more`));
    }
  }

  out.push('');
  return out;
}

function groupByFile(findings: Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = groups.get(finding.file);
    if (existing) existing.push(finding);
    else groups.set(finding.file, [finding]);
  }
  return groups;
}

/** Wrap prose to a width, indenting continuation lines. */
function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    if (current === '') {
      current = word;
    } else if (current.length + 1 + word.length <= width) {
      current += ` ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current !== '') lines.push(current);

  return lines.join(`\n${indent}`);
}

/** Compact one-line-per-finding format, useful for pre-commit hooks. */
export function formatCompact(result: ScanResult, painter: Painter): string {
  if (result.findings.length === 0) return '';
  return `${result.findings
    .map((f) =>
      [
        `${f.file}:${f.line}:${f.column}`,
        colorFor(painter, f.severity, SEVERITY_LABEL[f.severity].toLowerCase()),
        f.ruleId,
        f.message,
      ].join('  '),
    )
    .join('\n')}\n`;
}

export { severityRank };
