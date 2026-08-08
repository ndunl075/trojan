/**
 * Shared machinery for pattern-based rules.
 *
 * Most detectors are "run these regexes, but only where an LLM would read
 * prose". Rather than repeat that loop a dozen times, rules declare their
 * patterns and this builds the Rule object around them.
 */

import type { FileContext, RawFinding, Rule, RuleFamily, Severity } from '../types';

export interface PatternSpec {
  re: RegExp;
  /** Overrides the rule-level message for this pattern. */
  message?: string;
  /** Overrides the rule-level severity for this pattern. */
  severity?: Severity;
  /** Run this pattern everywhere, not just inside prose. */
  anywhere?: boolean;
  /**
   * Second-stage check. Regexes are cheap and blunt; this is where a rule
   * demands corroboration before reporting, which is how the tool avoids
   * flagging every README that mentions Claude.
   */
  confirm?: (match: RegExpExecArray, ctx: FileContext) => boolean;
}

export interface PatternRuleSpec {
  id: string;
  title: string;
  family: RuleFamily;
  severity: Severity;
  description: string;
  message: string;
  patterns: PatternSpec[];
  /** Default for patterns that do not set `anywhere`. Defaults to true. */
  proseOnly?: boolean;
}

export function patternRule(spec: PatternRuleSpec): Rule {
  const proseOnly = spec.proseOnly ?? true;

  return {
    id: spec.id,
    title: spec.title,
    family: spec.family,
    severity: spec.severity,
    description: spec.description,
    message: spec.message,
    scan(ctx: FileContext): RawFinding[] {
      const findings: RawFinding[] = [];

      for (const pattern of spec.patterns) {
        const restrictToProse = proseOnly && !pattern.anywhere;
        for (const match of execAll(pattern.re, ctx.text)) {
          if (restrictToProse && !ctx.inProse(match.index)) continue;
          if (pattern.confirm && !pattern.confirm(match, ctx)) continue;

          const finding: RawFinding = { ruleId: spec.id, index: match.index, match: match[0] };
          if (pattern.message) finding.message = pattern.message;
          if (pattern.severity) finding.severity = pattern.severity;
          findings.push(finding);
        }
      }

      return dedupe(findings);
    },
  };
}

/**
 * Iterate every match of a global regex without leaking `lastIndex` state
 * between files, and without spinning forever on a zero-width match.
 */
export function* execAll(re: RegExp, text: string): Generator<RegExpExecArray> {
  if (!re.global) {
    const match = re.exec(text);
    if (match) yield match;
    return;
  }

  re.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    yield match;
    if (match[0].length === 0) re.lastIndex += 1;
  }
  re.lastIndex = 0;
}

/**
 * Collapse overlapping matches from the same rule. Two patterns in a family
 * often fire on the same sentence; reporting it twice just makes the output
 * harder to read.
 */
export function dedupe(findings: RawFinding[]): RawFinding[] {
  if (findings.length < 2) return findings;

  const sorted = [...findings].sort((a, b) => a.index - b.index || b.match.length - a.match.length);
  const kept: RawFinding[] = [];
  let coveredTo = -1;

  for (const finding of sorted) {
    if (finding.index < coveredTo) continue;
    kept.push(finding);
    coveredTo = finding.index + finding.match.length;
  }

  return kept;
}

/** The line of text `index` sits on, without reading the whole file again. */
export function lineAround(text: string, index: number): string {
  const start = text.lastIndexOf('\n', index - 1) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  return text.slice(start, end);
}

/** `radius` characters either side of `index`, for proximity checks. */
export function windowAround(text: string, index: number, radius: number): string {
  return text.slice(Math.max(0, index - radius), Math.min(text.length, index + radius));
}

/** Words that turn a mention into a command. */
export const IMPERATIVE_RE =
  /\b(you (?:must|should|shall|will|need to|have to|are required to)|do not|don'?t|never|always|please|make sure|ensure that|be sure to|remember to|your task|your job|your goal|instead of|refrain from|immediately)\b/i;

/** Names of the agents an attacker would address directly. */
export const AGENT_NAME_RE =
  /\b(claude(?: code)?|anthropic|chatgpt|gpt-?[45o]?|openai|codex|copilot|cursor|windsurf|cline|roo ?code|aider|devin|continue\.dev|gemini|llama|language model|ai (?:assistant|agent|reviewer|model)|llm|coding (?:assistant|agent))\b/i;

export function hasImperativeNear(text: string, index: number, radius = 160): boolean {
  return IMPERATIVE_RE.test(windowAround(text, index, radius));
}

export function hasAgentNameNear(text: string, index: number, radius = 160): boolean {
  return AGENT_NAME_RE.test(windowAround(text, index, radius));
}
