#!/usr/bin/env node
/**
 * The command line interface.
 *
 * Argument parsing is hand-rolled for the same reason there are no runtime
 * dependencies: this is meant to sit in a pre-commit hook, and a hundred
 * milliseconds of module resolution is a hundred milliseconds every commit.
 */

import * as fsp from 'node:fs/promises';
import * as path from 'node:path';

import { AllowList, Baseline, BASELINE_FILENAME } from './baseline';
import { loadConfig, type TrojanConfig } from './config';
import { formatGithub, formatJson, formatNdjson, formatSarif } from './report/json';
import { formatCompact, formatTerminal } from './report/terminal';
import { ALL_RULES } from './rules';
import { scan, type ScanOptions } from './scanner';
import { isSeverity, SEVERITIES, severityRank, type Severity } from './types';
import { Painter } from './util/color';

const VERSION: string = (() => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return (require('../package.json') as { version: string }).version;
  } catch {
    return '0.0.0';
  }
})();

const FORMATS = ['human', 'compact', 'json', 'ndjson', 'sarif', 'github'] as const;
type Format = (typeof FORMATS)[number];

interface CliOptions {
  target: string;
  format: Format;
  severity: Severity;
  failOn: Severity | 'never';
  exclude: string[];
  include: string[];
  rules: string[];
  disableRules: string[];
  allow: string[];
  baseline: string | null;
  writeBaseline: string | null;
  showSuppressed: boolean;
  color: boolean | undefined;
  gitignore: boolean;
  followSymlinks: boolean;
  maxFileSize: number | undefined;
  maxFindings: number;
  concurrency: number | undefined;
  noBoost: boolean;
  quiet: boolean;
  output: string | null;
}

const HELP = `
trojan ${VERSION} - find prompt injections aimed at AI coding agents

  Scans a codebase for text written to manipulate an AI agent rather than
  inform a human: instruction overrides, forged role markers, planted trust
  assertions, and payloads hidden in invisible unicode or base64.

  Runs entirely on your machine. No network calls, ever.

USAGE
  npx trojan-scan <path> [options]
  trojan <path> [options]

OPTIONS
  -f, --format <name>       human, compact, json, ndjson, sarif, github  (human)
  -s, --severity <level>    minimum severity to report                   (low)
      --fail-on <level>     exit non-zero at this severity or above      (high)
                            use "never" to always exit 0
  -e, --exclude <glob>      skip paths matching a glob (repeatable)
      --include <glob>      scan only paths matching a glob (repeatable)
      --allow <regex>       drop findings matching a regex (repeatable)

  -b, --baseline <file>     suppress findings recorded in a baseline
                            (defaults to ./${BASELINE_FILENAME} if present)
      --write-baseline [f]  record current findings and exit
      --show-suppressed     list what the baseline is hiding

      --rules <ids>         run only these rules (comma separated)
      --disable-rule <id>   turn off a rule (repeatable)
      --list-rules          print every rule and exit

  -o, --output <file>       write the report to a file instead of stdout
      --no-color            disable ANSI colour
      --no-gitignore        do not honour .gitignore files
      --no-boost            do not raise severity for correlated findings
      --follow-symlinks     follow symbolic links while walking
      --max-file-size <kb>  skip files larger than this                  (2048)
      --max-findings <n>    stop reporting after n findings
      --concurrency <n>     files read in parallel                       (16)
  -q, --quiet               findings only, no header or summary
  -h, --help                show this help
  -v, --version             print the version

EXIT CODES
  0  clean, or findings all below --fail-on
  1  findings at or above --fail-on
  2  the scan could not run (bad flags, unreadable path)

EXAMPLES
  npx trojan-scan .
  npx trojan-scan ./node_modules/suspicious-pkg --severity medium
  npx trojan-scan . --format sarif -o trojan.sarif
  npx trojan-scan . --write-baseline && git add ${BASELINE_FILENAME}
`;

export async function main(argv: string[]): Promise<number> {
  let parsed: { options: CliOptions; earlyExit?: 'help' | 'version' | 'rules' };

  try {
    parsed = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`trojan: ${message(error)}\n\nRun \`trojan --help\` for usage.\n`);
    return 2;
  }

  if (parsed.earlyExit === 'help') {
    process.stdout.write(`${HELP.trim()}\n`);
    return 0;
  }
  if (parsed.earlyExit === 'version') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (parsed.earlyExit === 'rules') {
    process.stdout.write(renderRules(Painter.for(process.stdout, parsed.options.color)));
    return 0;
  }

  const cli = parsed.options;

  try {
    return await run(cli, argv);
  } catch (error) {
    process.stderr.write(`trojan: ${message(error)}\n`);
    return 2;
  }
}

async function run(cli: CliOptions, argv: string[]): Promise<number> {
  const targetPath = path.resolve(cli.target);

  let stat;
  try {
    stat = await fsp.stat(targetPath);
  } catch {
    throw new Error(`cannot read ${cli.target} - no such file or directory.`);
  }

  const configDir = stat.isDirectory() ? targetPath : path.dirname(targetPath);
  const { config } = await loadConfig(configDir);
  const merged = mergeConfig(cli, config, argv);

  const baselinePath = merged.baseline
    ? path.resolve(merged.baseline)
    : path.join(configDir, BASELINE_FILENAME);
  const baseline = merged.baseline
    ? await Baseline.load(baselinePath)
    : await Baseline.loadIfPresent(baselinePath);

  const scanOptions: ScanOptions = {
    exclude: merged.exclude,
    include: merged.include,
    respectGitignore: merged.gitignore,
    followSymlinks: merged.followSymlinks,
    minSeverity: merged.severity,
    rules: { only: merged.rules, disabled: merged.disableRules },
    baseline: merged.writeBaseline ? Baseline.empty() : baseline,
    allow: new AllowList(merged.allow),
    showSuppressed: merged.showSuppressed,
    maxFindings: merged.maxFindings,
    noBoost: merged.noBoost,
  };
  if (merged.maxFileSize !== undefined) scanOptions.maxFileSize = merged.maxFileSize * 1024;
  if (merged.concurrency !== undefined) scanOptions.concurrency = merged.concurrency;

  const result = await scan(targetPath, scanOptions);

  if (merged.writeBaseline) {
    const outPath = path.resolve(merged.writeBaseline);
    await Baseline.fromFindings(result.findings).write(outPath);
    process.stdout.write(
      `Wrote ${result.findings.length} finding${result.findings.length === 1 ? '' : 's'} to ${path.relative(process.cwd(), outPath) || outPath}\n` +
        'Future scans will not report them. Delete the file to start over.\n',
    );
    return 0;
  }

  const painter = Painter.for(merged.output ? ({ isTTY: false } as NodeJS.WriteStream) : process.stdout, merged.color);
  const rendered = render(result, merged, painter);

  if (merged.output) {
    await fsp.writeFile(path.resolve(merged.output), rendered, 'utf8');
    if (!merged.quiet) {
      process.stderr.write(
        `Wrote ${result.findings.length} finding${result.findings.length === 1 ? '' : 's'} to ${merged.output}\n`,
      );
    }
  } else {
    process.stdout.write(rendered);
  }

  if (merged.failOn === 'never') return 0;
  const threshold = severityRank(merged.failOn);
  const failing = result.findings.some((f) => severityRank(f.severity) >= threshold);
  return failing ? 1 : 0;
}

function render(
  result: Awaited<ReturnType<typeof scan>>,
  cli: CliOptions,
  painter: Painter,
): string {
  switch (cli.format) {
    case 'json':
      return formatJson(result, VERSION);
    case 'ndjson':
      return formatNdjson(result);
    case 'sarif':
      return formatSarif(result, VERSION);
    case 'github':
      return formatGithub(result);
    case 'compact':
      return formatCompact(result, painter);
    case 'human':
    default: {
      const options: Parameters<typeof formatTerminal>[1] = { painter };
      if (cli.quiet) options.quiet = true;
      if (result.suppressed.length > 0) options.showSuppressedCount = result.suppressed.length;
      return formatTerminal(result, options);
    }
  }
}

/** CLI flags win over the config file, which wins over defaults. */
function mergeConfig(cli: CliOptions, config: TrojanConfig, argv: string[]): CliOptions {
  const given = (...flags: string[]): boolean =>
    argv.some((arg) => flags.some((flag) => arg === flag || arg.startsWith(`${flag}=`)));

  const merged: CliOptions = { ...cli };

  if (config.exclude) merged.exclude = [...config.exclude, ...cli.exclude];
  if (config.include) merged.include = [...config.include, ...cli.include];
  if (config.allow) merged.allow = [...config.allow, ...cli.allow];
  if (config.rules && !given('--rules')) merged.rules = config.rules;
  if (config.disableRules) merged.disableRules = [...config.disableRules, ...cli.disableRules];
  if (config.severity && !given('-s', '--severity')) merged.severity = config.severity;
  if (config.failOn && !given('--fail-on')) merged.failOn = config.failOn;
  if (config.baseline && !given('-b', '--baseline')) merged.baseline = config.baseline;
  if (config.maxFileSize !== undefined && !given('--max-file-size')) {
    merged.maxFileSize = config.maxFileSize;
  }
  if (config.concurrency !== undefined && !given('--concurrency')) {
    merged.concurrency = config.concurrency;
  }
  if (config.respectGitignore !== undefined && !given('--no-gitignore')) {
    merged.gitignore = config.respectGitignore;
  }
  if (config.followSymlinks !== undefined && !given('--follow-symlinks')) {
    merged.followSymlinks = config.followSymlinks;
  }

  return merged;
}

export function parseArgs(argv: string[]): {
  options: CliOptions;
  earlyExit?: 'help' | 'version' | 'rules';
} {
  const options: CliOptions = {
    target: '.',
    format: 'human',
    severity: 'low',
    failOn: 'high',
    exclude: [],
    include: [],
    rules: [],
    disableRules: [],
    allow: [],
    baseline: null,
    writeBaseline: null,
    showSuppressed: false,
    color: undefined,
    gitignore: true,
    followSymlinks: false,
    maxFileSize: undefined,
    maxFindings: 0,
    concurrency: undefined,
    noBoost: false,
    quiet: false,
    output: null,
  };

  const positional: string[] = [];
  let i = 0;

  // Support both `--flag value` and `--flag=value`.
  const takeValue = (flag: string, inline: string | undefined): string => {
    if (inline !== undefined) return inline;
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('-')) {
      throw new Error(`${flag} needs a value.`);
    }
    i += 1;
    return next;
  };

  for (; i < argv.length; i += 1) {
    const arg = argv[i] as string;

    if (arg === '--') {
      positional.push(...argv.slice(i + 1));
      break;
    }

    if (!arg.startsWith('-') || arg === '-') {
      positional.push(arg);
      continue;
    }

    const equals = arg.indexOf('=');
    const flag = equals === -1 ? arg : arg.slice(0, equals);
    const inline = equals === -1 ? undefined : arg.slice(equals + 1);

    switch (flag) {
      case '-h':
      case '--help':
        return { options, earlyExit: 'help' };
      case '-v':
      case '--version':
        return { options, earlyExit: 'version' };
      case '--list-rules':
        return { options, earlyExit: 'rules' };

      case '-f':
      case '--format': {
        const value = takeValue(flag, inline);
        if (!(FORMATS as readonly string[]).includes(value)) {
          throw new Error(`unknown format "${value}". Choose from ${FORMATS.join(', ')}.`);
        }
        options.format = value as Format;
        break;
      }

      case '-s':
      case '--severity': {
        const value = takeValue(flag, inline);
        if (!isSeverity(value)) {
          throw new Error(`unknown severity "${value}". Choose from ${SEVERITIES.join(', ')}.`);
        }
        options.severity = value;
        break;
      }

      case '--fail-on': {
        const value = takeValue(flag, inline);
        if (!isSeverity(value) && value !== 'never') {
          throw new Error(
            `unknown severity "${value}" for --fail-on. Choose from ${SEVERITIES.join(', ')} or never.`,
          );
        }
        options.failOn = value as Severity | 'never';
        break;
      }

      case '-e':
      case '--exclude':
        options.exclude.push(takeValue(flag, inline));
        break;
      case '--include':
        options.include.push(takeValue(flag, inline));
        break;
      case '--allow':
        options.allow.push(takeValue(flag, inline));
        break;
      case '--rules':
        options.rules.push(...takeValue(flag, inline).split(',').map((s) => s.trim()).filter(Boolean));
        break;
      case '--disable-rule':
        options.disableRules.push(...takeValue(flag, inline).split(',').map((s) => s.trim()).filter(Boolean));
        break;

      case '-b':
      case '--baseline':
        options.baseline = takeValue(flag, inline);
        break;
      case '--write-baseline': {
        // The path is optional here, unlike every other value-taking flag.
        const next = argv[i + 1];
        if (inline !== undefined) options.writeBaseline = inline;
        else if (next !== undefined && !next.startsWith('-')) {
          options.writeBaseline = next;
          i += 1;
        } else options.writeBaseline = BASELINE_FILENAME;
        break;
      }
      case '--show-suppressed':
        options.showSuppressed = true;
        break;

      case '-o':
      case '--output':
        options.output = takeValue(flag, inline);
        break;

      case '--color':
        options.color = true;
        break;
      case '--no-color':
        options.color = false;
        break;
      case '--no-gitignore':
        options.gitignore = false;
        break;
      case '--no-boost':
        options.noBoost = true;
        break;
      case '--follow-symlinks':
        options.followSymlinks = true;
        break;

      case '--max-file-size':
        options.maxFileSize = positiveNumber(flag, takeValue(flag, inline));
        break;
      case '--max-findings':
        options.maxFindings = positiveNumber(flag, takeValue(flag, inline));
        break;
      case '--concurrency':
        options.concurrency = positiveNumber(flag, takeValue(flag, inline));
        break;

      case '-q':
      case '--quiet':
        options.quiet = true;
        break;

      default:
        throw new Error(`unknown option "${flag}".`);
    }
  }

  if (positional.length > 1) {
    throw new Error(
      `expected one path, got ${positional.length}. Use --include to narrow a scan instead.`,
    );
  }
  if (positional[0] !== undefined) options.target = positional[0];

  return { options };
}

function positiveNumber(flag: string, raw: string): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${flag} needs a positive number, got "${raw}".`);
  }
  return value;
}

function renderRules(painter: Painter): string {
  const lines: string[] = ['', painter.bold(`trojan ${VERSION} - ${ALL_RULES.length} rules`), ''];

  const byFamily = new Map<string, typeof ALL_RULES>();
  for (const rule of ALL_RULES) {
    const existing = byFamily.get(rule.family);
    if (existing) existing.push(rule);
    else byFamily.set(rule.family, [rule]);
  }

  for (const [family, rules] of byFamily) {
    lines.push(painter.magenta(`  ${family}`));
    for (const rule of rules) {
      lines.push(`    ${painter.cyan(rule.id)} ${painter.dim(`[${rule.severity}]`)}`);
      lines.push(`      ${rule.description}`);
    }
    lines.push('');
  }

  return `${lines.join('\n')}\n`;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      process.stderr.write(`trojan: ${message(error)}\n`);
      process.exitCode = 2;
    },
  );
}
