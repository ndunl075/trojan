/** The rule registry. */

import type { Rule } from '../types';
import { concealmentRules } from './concealment';
import { encodingRules } from './encoded';
import { languageRules } from './injection';
import { unicodeRules } from './unicode';

export const ALL_RULES: Rule[] = [
  ...languageRules,
  ...unicodeRules,
  ...encodingRules,
  ...concealmentRules,
];

const BY_ID = new Map(ALL_RULES.map((rule) => [rule.id, rule]));

export function getRule(id: string): Rule | undefined {
  return BY_ID.get(id);
}

export interface RuleSelection {
  /** When set, only these rule ids run. */
  only?: string[];
  /** Rule ids to drop. Applied after `only`. */
  disabled?: string[];
}

/** Resolve a selection into the rules to run, erroring on unknown ids. */
export function selectRules(selection: RuleSelection = {}): Rule[] {
  const unknown: string[] = [];
  for (const id of [...(selection.only ?? []), ...(selection.disabled ?? [])]) {
    if (!BY_ID.has(id)) unknown.push(id);
  }
  if (unknown.length > 0) {
    throw new Error(
      `Unknown rule id${unknown.length > 1 ? 's' : ''}: ${unknown.join(', ')}. Run \`trojan --list-rules\` to see the available ids.`,
    );
  }

  let rules = ALL_RULES;
  if (selection.only && selection.only.length > 0) {
    const wanted = new Set(selection.only);
    rules = rules.filter((rule) => wanted.has(rule.id));
  }
  if (selection.disabled && selection.disabled.length > 0) {
    const unwanted = new Set(selection.disabled);
    rules = rules.filter((rule) => !unwanted.has(rule.id));
  }
  return rules;
}

export * from './helpers';
