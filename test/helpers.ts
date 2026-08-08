import * as path from 'node:path';

import { scan, scanText, type ScanOptions } from '../src/scanner';
import { AllowList, Baseline } from '../src/baseline';
import { selectRules } from '../src/rules';
import type { Finding } from '../src/types';

/** Repo root, resolved from the compiled test location (.test-build/test). */
export const REPO_ROOT = path.resolve(__dirname, '..', '..');
export const FIXTURES = path.join(REPO_ROOT, 'test', 'fixtures');

export function fixture(...segments: string[]): string {
  return path.join(FIXTURES, ...segments);
}

/**
 * Scan a fixture directory with config discovery bypassed -- the repo's own
 * trojan.config.json excludes test/fixtures, which is correct for the repo and
 * useless for the tests.
 */
export function scanFixture(name: string, options: ScanOptions = {}) {
  return scan(fixture(name), { minSeverity: 'info', respectGitignore: false, ...options });
}

/** Run the full rule set over a string, as if it were a file at `filename`. */
export function detect(text: string, filename = 'sample.md'): Finding[] {
  return scanText(text, filename, path.join('/virtual', filename), {
    rules: selectRules(),
    baseline: Baseline.empty(),
    allow: new AllowList(),
    minRank: 0,
    noBoost: true,
    suppressedOut: [],
  });
}

export function ruleIds(findings: Finding[]): string[] {
  return [...new Set(findings.map((f) => f.ruleId))].sort();
}

export function hasRule(findings: Finding[], ruleId: string): boolean {
  return findings.some((f) => f.ruleId === ruleId);
}

/** Build a string of Unicode tag characters encoding `text`. */
export function tagEncode(text: string): string {
  return [...text].map((ch) => String.fromCodePoint(0xe0000 + ch.charCodeAt(0))).join('');
}

/** Build a variation-selector payload encoding the bytes of `text`. */
export function variationEncode(text: string): string {
  return [...Buffer.from(text, 'utf8')]
    .map((byte) => (byte < 16 ? String.fromCodePoint(0xfe00 + byte) : String.fromCodePoint(0xe0100 + byte - 16)))
    .join('');
}

export const ZWSP = '\u200b';
export const ZWNJ = '\u200c';
export const RLO = '\u202e';
export const PDF = '\u202c';
