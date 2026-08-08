/**
 * Programmatic API.
 *
 * The CLI is the primary interface, but the scanner is useful on its own --
 * an agent harness can call `scanText` on a file before handing it to a model,
 * which is closer to the point of the whole exercise than scanning after the
 * fact.
 */

export { scan, scanText, type ScanOptions } from './scanner';
export { ALL_RULES, getRule, selectRules, type RuleSelection } from './rules';
export {
  AllowList,
  Baseline,
  BASELINE_FILENAME,
  parseInlineIgnores,
  type BaselineEntry,
  type BaselineFile,
} from './baseline';
export { loadConfig, type TrojanConfig } from './config';
export {
  findProseSpans,
  isAgentInstructionFile,
  makeProseLookup,
  profileFor,
} from './prose';
export {
  walk,
  isTextCandidate,
  looksBinary,
  DEFAULT_EXCLUDES,
  TEXT_EXTENSIONS,
  type WalkOptions,
  type DiscoveredFile,
} from './walker';
export {
  buildJsonReport,
  formatGithub,
  formatJson,
  formatNdjson,
  formatSarif,
  type JsonReport,
} from './report/json';
export { formatCompact, formatTerminal } from './report/terminal';
export { Painter, supportsColor } from './util/color';
export { fingerprint, LineIndex, visualize } from './util/text';
export {
  bumpSeverity,
  isSeverity,
  severityRank,
  SEVERITIES,
  SEVERITY_RANK,
  type FileContext,
  type Finding,
  type ProseSpan,
  type RawFinding,
  type Rule,
  type RuleFamily,
  type ScanResult,
  type ScanStats,
  type Severity,
} from './types';
