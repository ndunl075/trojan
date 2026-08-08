/**
 * Unicode concealment detectors.
 *
 * This family matters more than the phrase matching, because it defeats the
 * one defence people assume they have: reading the diff. A tag-character
 * payload renders as literally nothing in every editor, terminal and code
 * review UI on the market, while a tokeniser sees it perfectly.
 *
 * These rules run over the whole file, not just prose. Invisible control
 * characters have no legitimate reason to sit in source code anywhere.
 */

import type { FileContext, RawFinding, Rule } from '../types';

/** Codepoints that render as nothing but survive a copy-paste. */
const INVISIBLE = new Set([
  0x00ad, // Soft hyphen
  0x180e, // Mongolian vowel separator
  0x200b, // Zero-width space
  0x200c, // Zero-width non-joiner
  0x200d, // Zero-width joiner
  0x2060, // Word joiner
  0x2061, // Function application
  0x2062, // Invisible times
  0x2063, // Invisible separator
  0x2064, // Invisible plus
  0x206a, 0x206b, 0x206c, 0x206d, 0x206e, 0x206f, // Deprecated format controls
  0x3164, // Hangul filler
  0x115f, 0x1160, // Hangul choseong/jungseong fillers
  0xffa0, // Halfwidth hangul filler
  0xfeff, // Zero-width no-break space (BOM when leading)
]);

/** Directional overrides -- the Trojan Source family (CVE-2021-42574). */
const BIDI = new Set([
  0x061c, // Arabic letter mark
  0x200e, 0x200f, // LRM / RLM
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // Embeddings and overrides
  0x2066, 0x2067, 0x2068, 0x2069, // Isolates
]);

const BIDI_NAMES: Record<number, string> = {
  0x061c: 'ARABIC LETTER MARK',
  0x200e: 'LEFT-TO-RIGHT MARK',
  0x200f: 'RIGHT-TO-LEFT MARK',
  0x202a: 'LEFT-TO-RIGHT EMBEDDING',
  0x202b: 'RIGHT-TO-LEFT EMBEDDING',
  0x202c: 'POP DIRECTIONAL FORMATTING',
  0x202d: 'LEFT-TO-RIGHT OVERRIDE',
  0x202e: 'RIGHT-TO-LEFT OVERRIDE',
  0x2066: 'LEFT-TO-RIGHT ISOLATE',
  0x2067: 'RIGHT-TO-LEFT ISOLATE',
  0x2068: 'FIRST STRONG ISOLATE',
  0x2069: 'POP DIRECTIONAL ISOLATE',
};

const TAG_START = 0xe0000;
const TAG_END = 0xe007f;

/** Iterate codepoints while keeping the UTF-16 index for reporting. */
function* codePoints(text: string): Generator<{ cp: number; index: number; width: number }> {
  let i = 0;
  while (i < text.length) {
    const cp = text.codePointAt(i) as number;
    const width = cp > 0xffff ? 2 : 1;
    yield { cp, index: i, width };
    i += width;
  }
}

function describeRun(codes: number[]): string {
  return codes.map((c) => `U+${c.toString(16).toUpperCase().padStart(4, '0')}`).join(' ');
}

/** Trim a decoded payload down to something safe to print in a terminal. */
function preview(text: string, limit = 120): string {
  const flattened = text.replace(/\s+/g, ' ').trim();
  return flattened.length > limit ? `${flattened.slice(0, limit)}...` : flattened;
}

/**
 * Unicode tag characters mirror ASCII 0x00-0x7F one-for-one, so any string can
 * be re-encoded into a sequence that occupies zero visual width. Decoding it
 * back is what makes this rule genuinely useful rather than just alarming.
 */
export const tagCharacters: Rule = {
  id: 'unicode/tag-characters',
  title: 'Invisible tag-character payload',
  family: 'unicode',
  severity: 'critical',
  description:
    'Unicode tag characters (U+E0000-U+E007F) that encode hidden ASCII text invisible in every editor.',
  message:
    'Hidden text encoded in Unicode tag characters. These render as nothing at all to a human reader while a model reads them as ordinary text.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];
    let run: { start: number; codes: number[] } | null = null;

    const flush = (endIndex: number): void => {
      if (!run) return;
      const decoded = run.codes
        .filter((cp) => cp > TAG_START && cp <= TAG_END)
        .map((cp) => String.fromCharCode(cp - TAG_START))
        .join('');
      const readable = decoded.replace(/[^\x20-\x7e]/g, '');

      findings.push({
        ruleId: 'unicode/tag-characters',
        index: run.start,
        match: ctx.text.slice(run.start, endIndex),
        message:
          readable.length >= 3
            ? `Hidden text encoded in invisible Unicode tag characters. It decodes to: "${preview(readable)}"`
            : `${run.codes.length} invisible Unicode tag characters. They render as nothing but are read as text by a model.`,
        detail: { decoded: preview(readable, 400), count: run.codes.length },
      });
      run = null;
    };

    for (const { cp, index } of codePoints(ctx.text)) {
      if (cp >= TAG_START && cp <= TAG_END) {
        if (!run) run = { start: index, codes: [] };
        run.codes.push(cp);
      } else if (run) {
        flush(index);
      }
    }
    flush(ctx.text.length);

    return findings;
  },
};

/**
 * Variation selectors carry no visual weight of their own, and there are 256
 * of them across two blocks -- exactly enough to encode arbitrary bytes. The
 * technique showed up publicly in 2024 as "emoji smuggling".
 */
export const variationSelectors: Rule = {
  id: 'unicode/variation-selector-payload',
  title: 'Variation-selector byte smuggling',
  family: 'unicode',
  severity: 'critical',
  description:
    'Long runs of Unicode variation selectors, which can encode arbitrary bytes with zero visual width.',
  message:
    'A run of Unicode variation selectors. A handful after an emoji is normal; a long run is a byte-level payload hidden in plain sight.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];
    // Three or more in sequence is well past any legitimate emoji styling.
    const threshold = 3;
    let run: { start: number; codes: number[] } | null = null;

    const isSelector = (cp: number): boolean =>
      (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);

    const flush = (endIndex: number): void => {
      if (!run) return;
      if (run.codes.length >= threshold) {
        const bytes = run.codes.map((cp) =>
          cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16,
        );
        const decoded = Buffer.from(bytes).toString('utf8').replace(/[^\x20-\x7e]/g, '');
        findings.push({
          ruleId: 'unicode/variation-selector-payload',
          index: run.start,
          match: ctx.text.slice(run.start, endIndex),
          message:
            decoded.length >= 4
              ? `${run.codes.length} variation selectors encoding hidden bytes. They decode to: "${preview(decoded)}"`
              : `${run.codes.length} consecutive variation selectors with no visible glyph. This is a byte-smuggling payload, not text styling.`,
          detail: { decoded: preview(decoded, 400), count: run.codes.length },
        });
      }
      run = null;
    };

    for (const { cp, index } of codePoints(ctx.text)) {
      if (isSelector(cp)) {
        if (!run) run = { start: index, codes: [] };
        run.codes.push(cp);
      } else if (run) {
        flush(index);
      }
    }
    flush(ctx.text.length);

    return findings;
  },
};

/** Zero-width characters. Sometimes accidental, never load-bearing in source. */
export const invisibleCharacters: Rule = {
  id: 'unicode/invisible-characters',
  title: 'Zero-width characters',
  family: 'unicode',
  severity: 'high',
  description:
    'Zero-width or otherwise non-rendering characters embedded in file content.',
  message:
    'Zero-width characters in the file. They are invisible in review but are still tokens to a model, and are commonly used to hide instructions or to break up strings that would otherwise be flagged.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];
    let run: { start: number; codes: number[] } | null = null;

    const flush = (endIndex: number): void => {
      if (!run) return;
      const { start, codes } = run;
      run = null;

      // A single ZWJ inside an emoji sequence is legitimate; skip it.
      if (codes.length === 1 && codes[0] === 0x200d && looksLikeEmojiJoin(ctx.text, start)) return;

      findings.push({
        ruleId: 'unicode/invisible-characters',
        index: start,
        match: ctx.text.slice(start, endIndex),
        severity: codes.length >= 8 ? 'critical' : 'high',
        message:
          codes.length >= 8
            ? `A run of ${codes.length} zero-width characters (${describeRun(codes.slice(0, 6))}...). A run this long is carrying data, not formatting.`
            : `${codes.length} zero-width character(s) (${describeRun(codes)}). Invisible to a reviewer, still read by a model.`,
        detail: { count: codes.length, codepoints: describeRun(codes.slice(0, 20)) },
      });
    };

    for (const { cp, index } of codePoints(ctx.text)) {
      // A leading BOM is ordinary file metadata.
      const isLeadingBom = cp === 0xfeff && index === 0;
      if (INVISIBLE.has(cp) && !isLeadingBom) {
        if (!run) run = { start: index, codes: [] };
        run.codes.push(cp);
      } else if (run) {
        flush(index);
      }
    }
    flush(ctx.text.length);

    return findings;
  },
};

function looksLikeEmojiJoin(text: string, index: number): boolean {
  const before = text.codePointAt(Math.max(0, index - 2));
  const after = text.codePointAt(index + 1);
  const isPictographic = (cp: number | undefined): boolean =>
    cp !== undefined && ((cp >= 0x1f000 && cp <= 0x1faff) || (cp >= 0x2600 && cp <= 0x27bf));
  return isPictographic(before) && isPictographic(after);
}

/**
 * Trojan Source. Directional overrides let the visual order of a line differ
 * from its logical order, so a reviewer and a compiler read different programs.
 */
export const bidiControls: Rule = {
  id: 'unicode/bidi-override',
  title: 'Bidirectional text override',
  family: 'unicode',
  severity: 'critical',
  description:
    'Bidi control characters that make source render differently from how it is parsed (Trojan Source, CVE-2021-42574).',
  message:
    'A bidirectional control character. These reorder how a line displays without changing how it is parsed, so what you read is not what runs.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];

    for (const { cp, index } of codePoints(ctx.text)) {
      if (!BIDI.has(cp)) continue;
      const name = BIDI_NAMES[cp] ?? `U+${cp.toString(16).toUpperCase()}`;
      // Marks are weak controls and show up in real localisation work.
      const isWeakMark = cp === 0x200e || cp === 0x200f || cp === 0x061c;
      findings.push({
        ruleId: 'unicode/bidi-override',
        index,
        match: ctx.text[index] as string,
        severity: isWeakMark ? 'medium' : 'critical',
        message: isWeakMark
          ? `${name} (U+${cp.toString(16).toUpperCase()}). Legitimate in localised text, but it still changes how this line renders.`
          : `${name} (U+${cp.toString(16).toUpperCase()}). This makes the line display in a different order than it is parsed, the Trojan Source technique.`,
        detail: { control: name },
      });
    }

    return findings;
  },
};

/** Latin-lookalike letters from other scripts, used to disguise words. */
const HOMOGLYPHS: Record<string, string> = {
  а: 'a', в: 'b', с: 'c', е: 'e', һ: 'h', і: 'i', ј: 'j', к: 'k', м: 'm',
  о: 'o', р: 'p', ѕ: 's', т: 't', у: 'y', х: 'x', А: 'A', В: 'B', С: 'C',
  Е: 'E', Н: 'H', К: 'K', М: 'M', О: 'O', Р: 'P', Ѕ: 'S', Т: 'T', Х: 'X',
  ɑ: 'a', ɡ: 'g', ᴀ: 'A', ο: 'o', ρ: 'p', ν: 'v', κ: 'k', Α: 'A', Β: 'B',
  Ε: 'E', Ζ: 'Z', Η: 'H', Ι: 'I', Κ: 'K', Μ: 'M', Ν: 'N', Ο: 'O', Ρ: 'P',
  Τ: 'T', Υ: 'Y', Χ: 'X',
};

export const homoglyphs: Rule = {
  id: 'unicode/homoglyph',
  title: 'Script-mixing homoglyph',
  family: 'unicode',
  severity: 'medium',
  description:
    'Non-Latin characters that look identical to Latin ones, mixed into otherwise-ASCII words.',
  message:
    'A word mixes Latin characters with lookalikes from another script. This is used to slip past exact-match filters while looking unchanged to a reader.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];
    // Words that are mostly ASCII but contain at least one lookalike.
    const wordRe = /[\p{L}\p{M}\p{Nd}_]{3,}/gu;

    for (const match of ctx.text.matchAll(wordRe)) {
      const word = match[0];
      let ascii = 0;
      let lookalike = '';

      for (const ch of word) {
        if (ch.charCodeAt(0) < 128) ascii += 1;
        else if (HOMOGLYPHS[ch]) lookalike += ch;
      }

      if (lookalike === '' || ascii === 0) continue;
      // Require the word to be predominantly ASCII, otherwise it is just
      // ordinary text in another language.
      if (ascii < word.length - lookalike.length) continue;
      if (ascii / word.length < 0.5) continue;

      const normalised = [...word].map((ch) => HOMOGLYPHS[ch] ?? ch).join('');
      findings.push({
        ruleId: 'unicode/homoglyph',
        index: match.index ?? 0,
        match: word,
        message: `"${word}" mixes scripts and reads as "${normalised}". A reviewer sees the second spelling; a byte comparison sees the first.`,
        detail: { normalised, lookalikes: lookalike },
      });
    }

    return findings;
  },
};

/**
 * NUL and other C0 control bytes inside a text file.
 *
 * These are worth their own rule because they attack the *scanner* rather than
 * the model. Plenty of tools treat a NUL as end-of-string or as proof that a
 * file is binary and skip it entirely, so a single planted byte can take a
 * whole file out of review while leaving it perfectly readable to anything
 * that reads it as UTF-8.
 */
export const controlCharacters: Rule = {
  id: 'unicode/control-characters',
  title: 'Parser-hostile control characters',
  family: 'unicode',
  severity: 'high',
  description:
    'NUL or other C0 control bytes in a text file, which make many tools treat it as binary and skip it.',
  message:
    'Control bytes in a text file. Many scanners and diff tools treat these as end-of-file or as proof the file is binary, so they are a cheap way to hide the rest of a file from review.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];
    let run: { start: number; codes: number[] } | null = null;

    const isHostile = (cp: number): boolean =>
      cp === 0 || (cp < 32 && cp !== 9 && cp !== 10 && cp !== 13) || cp === 0x7f;

    const flush = (endIndex: number): void => {
      if (!run) return;
      const { start, codes } = run;
      run = null;

      const hasNul = codes.includes(0);
      findings.push({
        ruleId: 'unicode/control-characters',
        index: start,
        match: ctx.text.slice(start, endIndex),
        severity: hasNul ? 'high' : 'medium',
        message: hasNul
          ? `${codes.length} control byte(s) including a NUL (${describeRun(codes.slice(0, 6))}). A NUL in a text file makes many tools stop reading or skip the file entirely.`
          : `${codes.length} C0 control character(s) (${describeRun(codes.slice(0, 6))}) in a text file. They render as nothing and confuse tools that read the file as text.`,
        detail: { count: codes.length, codepoints: describeRun(codes.slice(0, 20)) },
      });
    };

    for (const { cp, index } of codePoints(ctx.text)) {
      if (isHostile(cp)) {
        if (!run) run = { start: index, codes: [] };
        run.codes.push(cp);
      } else if (run) {
        flush(index);
      }
    }
    flush(ctx.text.length);

    return findings;
  },
};

export const unicodeRules: Rule[] = [
  tagCharacters,
  variationSelectors,
  invisibleCharacters,
  bidiControls,
  homoglyphs,
  controlCharacters,
];
