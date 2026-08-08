/**
 * Machine-readable output.
 *
 * Two shapes: a native JSON report for scripting, and SARIF 2.1.0 so GitHub
 * code scanning renders findings inline on a pull request. SARIF is worth the
 * extra sixty lines -- it is the difference between a red CI check and an
 * annotation on the offending line.
 */

import { SEVERITIES, type Finding, type ScanResult, type Severity } from '../types';
import { ALL_RULES } from '../rules';

export interface JsonReport {
  tool: { name: string; version: string };
  root: string;
  generatedAt: string;
  summary: {
    total: number;
    bySeverity: Record<Severity, number>;
    filesScanned: number;
    filesSkipped: number;
    durationMs: number;
  };
  findings: Finding[];
  suppressed: Finding[];
  errors: { file: string; message: string }[];
}

export function buildJsonReport(result: ScanResult, version: string): JsonReport {
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const finding of result.findings) bySeverity[finding.severity] += 1;

  return {
    tool: { name: 'trojan', version },
    root: result.root,
    generatedAt: new Date().toISOString(),
    summary: {
      total: result.findings.length,
      bySeverity,
      filesScanned: result.stats.filesScanned,
      filesSkipped: result.stats.filesSkipped,
      durationMs: result.stats.durationMs,
    },
    findings: result.findings,
    suppressed: result.suppressed,
    errors: result.errors,
  };
}

export function formatJson(result: ScanResult, version: string, pretty = true): string {
  const report = buildJsonReport(result, version);
  return `${JSON.stringify(report, null, pretty ? 2 : 0)}\n`;
}

/** One JSON object per finding. Convenient for `jq` and log pipelines. */
export function formatNdjson(result: ScanResult): string {
  if (result.findings.length === 0) return '';
  return `${result.findings.map((f) => JSON.stringify(f)).join('\n')}\n`;
}

const SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** GitHub weights results by this 0-10 score when deduplicating alerts. */
const SARIF_RANK: Record<Severity, number> = {
  critical: 9.5,
  high: 8,
  medium: 5,
  low: 3,
  info: 1,
};

export function formatSarif(result: ScanResult, version: string): string {
  const usedRuleIds = new Set(result.findings.map((f) => f.ruleId));
  const rules = ALL_RULES.filter((rule) => usedRuleIds.has(rule.id)).map((rule) => ({
    id: rule.id,
    name: rule.title.replace(/[^A-Za-z0-9]/g, ''),
    shortDescription: { text: rule.title },
    fullDescription: { text: rule.description },
    defaultConfiguration: { level: SARIF_LEVEL[rule.severity] },
    properties: {
      tags: ['security', 'prompt-injection', rule.family],
      'security-severity': String(SARIF_RANK[rule.severity]),
    },
  }));

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'trojan',
            version,
            informationUri: 'https://github.com/ndunl075/trojan',
            rules,
          },
        },
        results: result.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: SARIF_LEVEL[finding.severity],
          message: { text: finding.message },
          properties: {
            'security-severity': String(SARIF_RANK[finding.severity]),
            fingerprint: finding.fingerprint,
          },
          partialFingerprints: { trojanFingerprint: finding.fingerprint },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file, uriBaseId: '%SRCROOT%' },
                region: {
                  startLine: finding.line,
                  startColumn: finding.column,
                  snippet: { text: finding.snippet },
                },
              },
            },
          ],
        })),
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

/** GitHub Actions workflow-command annotations. */
export function formatGithub(result: ScanResult): string {
  if (result.findings.length === 0) return '';
  return `${result.findings
    .map((finding) => {
      const level = finding.severity === 'medium' ? 'warning' : finding.severity === 'critical' || finding.severity === 'high' ? 'error' : 'notice';
      const title = escapeProperty(`trojan: ${finding.ruleTitle}`);
      const message = escapeData(`${finding.message} (${finding.ruleId})`);
      return `::${level} file=${escapeProperty(finding.file)},line=${finding.line},col=${finding.column},title=${title}::${message}`;
    })
    .join('\n')}\n`;
}

function escapeData(text: string): string {
  return text.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeProperty(text: string): string {
  return escapeData(text).replace(/:/g, '%3A').replace(/,/g, '%2C');
}
