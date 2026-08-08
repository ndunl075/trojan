/**
 * Core vocabulary shared by the walker, the rules and the reporters.
 *
 * Everything here is plain data. Rules never touch the filesystem and
 * reporters never touch rules -- that separation is what makes the whole
 * thing testable without fixtures on disk.
 */

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;

export type Severity = (typeof SEVERITIES)[number];

/** Numeric rank so thresholds and "bump by one" boosts are trivial. */
export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityRank(s: Severity): number {
  return SEVERITY_RANK[s];
}

export function bumpSeverity(s: Severity, by = 1): Severity {
  const next = Math.min(SEVERITIES.length - 1, Math.max(0, severityRank(s) + by));
  return SEVERITIES[next] as Severity;
}

export function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

/**
 * Rule families. When a single file trips two or more *different* families we
 * treat that as corroboration and boost severity -- one suspicious phrase is
 * noise, three of them stacked in a README is an attack.
 */
export type RuleFamily =
  | 'override'
  | 'role'
  | 'trust'
  | 'targeting'
  | 'exfil'
  | 'tooling'
  | 'unicode'
  | 'encoding'
  | 'concealment'
  | 'agent-config';

/** What a rule hands back. The scanner fills in the rest. */
export interface RawFinding {
  ruleId: string;
  /** Byte-agnostic offset into the file text where the match starts. */
  index: number;
  /** The exact text that matched. Reporters truncate and escape it. */
  match: string;
  /** Plain-language reason, specific to this match where possible. */
  message?: string;
  /** Overrides the rule's default severity for this particular match. */
  severity?: Severity;
  /** Extra machine-readable detail, e.g. decoded payloads. */
  detail?: Record<string, string | number | boolean>;
}

/** A finding with location and identity resolved. */
export interface Finding {
  ruleId: string;
  ruleTitle: string;
  family: RuleFamily;
  severity: Severity;
  /** Severity before any correlation or agent-config boost was applied. */
  baseSeverity: Severity;
  /** Path relative to the scan root, always with forward slashes. */
  file: string;
  line: number;
  column: number;
  /** The matched text, truncated and control-character escaped. */
  snippet: string;
  /** The full source line the match sits on, truncated and escaped. */
  context: string;
  /** Why a human should care, in plain language. */
  message: string;
  /** Stable across line-number churn, used for baselining. */
  fingerprint: string;
  /** Set when severity was raised because the file tripped several families. */
  boostedBy?: string;
  detail?: Record<string, string | number | boolean>;
}

/** A region of a file that reads as prose to an LLM: comments, docstrings, markdown. */
export interface ProseSpan {
  start: number;
  end: number;
  kind: 'comment' | 'string' | 'document';
}

/** Everything a rule is given about one file. */
export interface FileContext {
  /** Path relative to the scan root, forward slashes. */
  path: string;
  /** Absolute path on disk. */
  absolutePath: string;
  /** Lowercased extension including the dot, or '' when there is none. */
  ext: string;
  /** Basename, original case. */
  basename: string;
  /** Full decoded file text. */
  text: string;
  /** Regions an LLM would read as instructions rather than code. */
  prose: ProseSpan[];
  /** True when the whole file is prose (markdown, plaintext, agent configs). */
  isDocument: boolean;
  /** True when the file is auto-loaded as instructions by a coding agent. */
  isAgentInstructionFile: boolean;
  /** True when `index` falls inside a prose span. */
  inProse(index: number): boolean;
}

export interface Rule {
  id: string;
  title: string;
  family: RuleFamily;
  severity: Severity;
  /** One sentence a maintainer can read in `--list-rules`. */
  description: string;
  /** Default message when a raw finding does not supply its own. */
  message: string;
  scan(ctx: FileContext): RawFinding[];
}

export interface ScanStats {
  filesScanned: number;
  filesSkipped: number;
  bytesScanned: number;
  durationMs: number;
}

export interface ScanResult {
  /** Absolute path of the directory (or file) that was scanned. */
  root: string;
  findings: Finding[];
  /** Findings suppressed by a baseline entry or an inline ignore comment. */
  suppressed: Finding[];
  stats: ScanStats;
  errors: { file: string; message: string }[];
}
