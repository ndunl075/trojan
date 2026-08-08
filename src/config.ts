/**
 * Optional project configuration.
 *
 * Everything here is also a CLI flag; the file exists so a repo can commit its
 * policy once instead of every contributor remembering the same six flags.
 * CLI flags win over the file, which wins over defaults.
 */

import * as fsp from 'node:fs/promises';
import * as path from 'node:path';

import { isSeverity, type Severity } from './types';

export const CONFIG_FILENAMES = [
  'trojan.config.json',
  '.trojanrc.json',
  '.trojanrc',
];

export interface TrojanConfig {
  exclude?: string[];
  include?: string[];
  /** Minimum severity to report. */
  severity?: Severity;
  /** Severity at or above which the process exits non-zero. */
  failOn?: Severity | 'never';
  rules?: string[];
  disableRules?: string[];
  /** Regexes; a finding whose snippet or line matches one is dropped. */
  allow?: string[];
  baseline?: string;
  maxFileSize?: number;
  respectGitignore?: boolean;
  followSymlinks?: boolean;
  concurrency?: number;
}

const KNOWN_KEYS = new Set<keyof TrojanConfig>([
  'exclude', 'include', 'severity', 'failOn', 'rules', 'disableRules', 'allow',
  'baseline', 'maxFileSize', 'respectGitignore', 'followSymlinks', 'concurrency',
]);

/**
 * Look for a config file in `startDir`, then in each ancestor up to the
 * filesystem root. Also honours a `trojan` key in package.json, which is where
 * most JS projects would look first.
 */
export async function loadConfig(
  startDir: string,
): Promise<{ config: TrojanConfig; path: string | null }> {
  let dir = path.resolve(startDir);

  for (;;) {
    for (const filename of CONFIG_FILENAMES) {
      const candidate = path.join(dir, filename);
      const parsed = await readJson(candidate);
      if (parsed !== null) {
        return { config: validate(parsed, candidate), path: candidate };
      }
    }

    const packageJsonPath = path.join(dir, 'package.json');
    const packageJson = await readJson(packageJsonPath);
    if (packageJson !== null && typeof packageJson === 'object') {
      const section = (packageJson as Record<string, unknown>)['trojan'];
      if (section !== undefined) {
        return { config: validate(section, `${packageJsonPath} ("trojan")`), path: packageJsonPath };
      }
    }

    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  return { config: {}, path: null };
}

async function readJson(file: string): Promise<unknown | null> {
  let raw: string;
  try {
    raw = await fsp.readFile(file, 'utf8');
  } catch {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `${file} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function validate(value: unknown, source: string): TrojanConfig {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${source} must contain a JSON object.`);
  }

  const input = value as Record<string, unknown>;
  const config: TrojanConfig = {};

  for (const key of Object.keys(input)) {
    if (!KNOWN_KEYS.has(key as keyof TrojanConfig) && key !== '$schema') {
      throw new Error(
        `${source}: unknown option "${key}". Valid options: ${[...KNOWN_KEYS].join(', ')}.`,
      );
    }
  }

  const stringArray = (key: keyof TrojanConfig): string[] | undefined => {
    const raw = input[key];
    if (raw === undefined) return undefined;
    if (!Array.isArray(raw) || raw.some((item) => typeof item !== 'string')) {
      throw new Error(`${source}: "${key}" must be an array of strings.`);
    }
    return raw as string[];
  };

  const severityValue = (key: 'severity' | 'failOn'): Severity | 'never' | undefined => {
    const raw = input[key];
    if (raw === undefined) return undefined;
    if (typeof raw !== 'string' || (!isSeverity(raw) && raw !== 'never')) {
      throw new Error(
        `${source}: "${key}" must be one of info, low, medium, high, critical${key === 'failOn' ? ', never' : ''}.`,
      );
    }
    return raw as Severity | 'never';
  };

  const numberValue = (key: 'maxFileSize' | 'concurrency'): number | undefined => {
    const raw = input[key];
    if (raw === undefined) return undefined;
    if (typeof raw !== 'number' || !Number.isFinite(raw) || raw <= 0) {
      throw new Error(`${source}: "${key}" must be a positive number.`);
    }
    return raw;
  };

  const boolValue = (key: 'respectGitignore' | 'followSymlinks'): boolean | undefined => {
    const raw = input[key];
    if (raw === undefined) return undefined;
    if (typeof raw !== 'boolean') throw new Error(`${source}: "${key}" must be true or false.`);
    return raw;
  };

  assign(config, 'exclude', stringArray('exclude'));
  assign(config, 'include', stringArray('include'));
  assign(config, 'rules', stringArray('rules'));
  assign(config, 'disableRules', stringArray('disableRules'));
  assign(config, 'allow', stringArray('allow'));
  assign(config, 'severity', severityValue('severity') as Severity | undefined);
  assign(config, 'failOn', severityValue('failOn'));
  assign(config, 'maxFileSize', numberValue('maxFileSize'));
  assign(config, 'concurrency', numberValue('concurrency'));
  assign(config, 'respectGitignore', boolValue('respectGitignore'));
  assign(config, 'followSymlinks', boolValue('followSymlinks'));

  if (input['baseline'] !== undefined) {
    if (typeof input['baseline'] !== 'string') {
      throw new Error(`${source}: "baseline" must be a path.`);
    }
    config.baseline = input['baseline'];
  }

  return config;
}

function assign<K extends keyof TrojanConfig>(
  config: TrojanConfig,
  key: K,
  value: TrojanConfig[K] | undefined,
): void {
  if (value !== undefined) config[key] = value;
}
