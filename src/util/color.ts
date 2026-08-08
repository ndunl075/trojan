/**
 * A small ANSI helper, so the package can stay dependency-free.
 *
 * Honours NO_COLOR and FORCE_COLOR, and falls back to plain text whenever
 * stdout is not a TTY -- which is what makes piping the human format into a
 * file or a CI log produce something readable.
 */

const ESC = '\u001b[';

const CODES = {
  reset: 0,
  bold: 1,
  dim: 2,
  italic: 3,
  underline: 4,
  red: 31,
  green: 32,
  yellow: 33,
  blue: 34,
  magenta: 35,
  cyan: 36,
  white: 37,
  gray: 90,
  brightRed: 91,
  brightYellow: 93,
} as const;

export type ColorName = keyof typeof CODES;

export function supportsColor(stream: NodeJS.WriteStream = process.stdout): boolean {
  if (process.env['NO_COLOR'] !== undefined && process.env['NO_COLOR'] !== '') return false;
  if (process.env['FORCE_COLOR'] === '0') return false;
  if (process.env['FORCE_COLOR'] !== undefined) return true;
  if (process.env['TERM'] === 'dumb') return false;
  if (process.env['CI'] !== undefined && process.env['CI'] !== '') return true;
  return Boolean(stream.isTTY);
}

export class Painter {
  private readonly enabled: boolean;

  constructor(enabled: boolean) {
    this.enabled = enabled;
  }

  static for(stream: NodeJS.WriteStream = process.stdout, force?: boolean): Painter {
    return new Painter(force ?? supportsColor(stream));
  }

  get isEnabled(): boolean {
    return this.enabled;
  }

  paint(text: string, ...names: ColorName[]): string {
    if (!this.enabled || names.length === 0) return text;
    const open = names.map((name) => `${ESC}${CODES[name]}m`).join('');
    return `${open}${text}${ESC}${CODES.reset}m`;
  }

  bold(text: string): string {
    return this.paint(text, 'bold');
  }

  dim(text: string): string {
    return this.paint(text, 'dim');
  }

  red(text: string): string {
    return this.paint(text, 'red');
  }

  green(text: string): string {
    return this.paint(text, 'green');
  }

  yellow(text: string): string {
    return this.paint(text, 'yellow');
  }

  blue(text: string): string {
    return this.paint(text, 'blue');
  }

  cyan(text: string): string {
    return this.paint(text, 'cyan');
  }

  gray(text: string): string {
    return this.paint(text, 'gray');
  }

  magenta(text: string): string {
    return this.paint(text, 'magenta');
  }
}

/** Length of a string as rendered, ignoring escape sequences. */
export function visibleLength(text: string): number {
  return text.replace(/\u001b\[[0-9;]*m/g, '').length;
}
