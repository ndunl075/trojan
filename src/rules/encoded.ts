/**
 * Obfuscated payload detectors.
 *
 * An attacker who expects a scanner to grep for "ignore previous instructions"
 * simply base64s it. The counter is to decode candidate blobs cheaply and run
 * the language rules over the *result*, so obfuscation costs the attacker a
 * detection rather than buying them one.
 *
 * Decoding is bounded on purpose: only runs above a length threshold, only the
 * first few kilobytes of each, and only one level deep. This rule must never
 * become the reason a scan is slow.
 */

import type { FileContext, RawFinding, Rule } from '../types';
import { execAll } from './helpers';

/** Phrases worth finding *after* a decode. Deliberately narrow, since a hit here is damning. */
const DECODED_INJECTION_RE =
  /\b(?:ignore\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|earlier)|forget\s+everything|system\s*prompt|you\s+are\s+(?:now\s+)?an?\s+|do\s+not\s+(?:flag|report|tell|mention)|new\s+instructions?|disregard\s+(?:previous|prior|all)|<\|im_start\|>|\[INST\]|as\s+an?\s+AI|assistant\s*:|your\s+(?:real|true|new)\s+task)\b/i;

/** Commands worth finding after a decode, for the payload-dropper case. */
const DECODED_COMMAND_RE =
  /\b(?:curl\s+[^\s]+\s*\|\s*(?:ba)?sh|wget\s+[^\s]+\s*\|\s*(?:ba)?sh|rm\s+-rf\s+\/|child_process|require\s*\(\s*['"]child_process|eval\s*\(|Invoke-Expression|powershell\s+-enc|base64\s+-d|os\.system|subprocess\.(?:call|run|Popen)|\/bin\/(?:ba)?sh\s+-c)\b/i;

const MAX_DECODE_LENGTH = 8192;

function printableRatio(text: string): number {
  if (text.length === 0) return 0;
  let printable = 0;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126)) printable += 1;
  }
  return printable / text.length;
}

/** Does this decode to something that reads like English rather than binary noise? */
function looksLikeProse(text: string): boolean {
  if (printableRatio(text) < 0.85) return false;
  const words = text.match(/\b[a-z]{2,}\b/gi);
  if (!words || words.length < 4) return false;
  return /\b(?:the|you|and|are|this|that|not|for|with|your|all|any|is|to|do)\b/i.test(text);
}

function decodeBase64(candidate: string): string | null {
  try {
    const buffer = Buffer.from(candidate, 'base64');
    // Node's decoder is lenient; make sure it actually consumed the input.
    if (buffer.length < 8) return null;
    if (Math.abs(buffer.length - (candidate.length * 3) / 4) > 3) return null;
    return buffer.toString('utf8');
  } catch {
    return null;
  }
}

/**
 * String.fromCodePoint throws on anything above U+10FFFF, and an escape
 * sequence in a scanned file is attacker-controlled. A thrown decoder would
 * take this rule down for the whole file -- which is a free way to disable the
 * detector -- so out-of-range escapes decode to nothing instead.
 */
function safeFromCodePoint(value: number): string {
  if (!Number.isInteger(value) || value < 0 || value > 0x10ffff) return '';
  // Lone surrogates are valid input to fromCodePoint but produce broken text.
  if (value >= 0xd800 && value <= 0xdfff) return '';
  return String.fromCodePoint(value);
}

function truncate(text: string, limit = 160): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > limit ? `${flat.slice(0, limit)}...` : flat;
}

/** Base64 blobs whose plaintext is an instruction. */
export const base64Payload: Rule = {
  id: 'encoding/base64-instruction',
  title: 'Base64-encoded instruction',
  family: 'encoding',
  severity: 'critical',
  description:
    'Base64 strings that decode to prompt-injection language or shell commands.',
  message: 'A base64 blob that decodes to instruction text.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];
    const re = /[A-Za-z0-9+/]{24,}={0,2}/g;

    for (const match of execAll(re, ctx.text)) {
      const candidate = match[0];
      if (candidate.length > MAX_DECODE_LENGTH) continue;
      // Hashes, minified identifiers and git SHAs are the main noise source;
      // real base64 text has mixed case and usually some digits.
      if (!/[a-z]/.test(candidate) || !/[A-Z]/.test(candidate)) continue;

      const decoded = decodeBase64(candidate);
      if (!decoded) continue;

      const injection = DECODED_INJECTION_RE.test(decoded);
      const command = DECODED_COMMAND_RE.test(decoded);

      if (injection) {
        findings.push({
          ruleId: 'encoding/base64-instruction',
          index: match.index,
          match: candidate,
          severity: 'critical',
          message: `Base64 that decodes to prompt-injection text: "${truncate(decoded)}"`,
          detail: { decoded: truncate(decoded, 500) },
        });
        continue;
      }

      if (command) {
        findings.push({
          ruleId: 'encoding/base64-instruction',
          index: match.index,
          match: candidate,
          severity: 'high',
          message: `Base64 that decodes to executable commands: "${truncate(decoded)}"`,
          detail: { decoded: truncate(decoded, 500) },
        });
        continue;
      }

      // Encoded English prose inside a comment is odd on its own.
      if (ctx.inProse(match.index) && looksLikeProse(decoded)) {
        findings.push({
          ruleId: 'encoding/base64-instruction',
          index: match.index,
          match: candidate,
          severity: 'medium',
          message: `A comment contains base64 that decodes to readable English: "${truncate(decoded)}". Documentation has no reason to be encoded.`,
          detail: { decoded: truncate(decoded, 500) },
        });
      }
    }

    return findings;
  },
};

/**
 * The same trick without base64: `ig...`, `\x69\x67...`, decimal
 * character codes, or percent-encoding.
 */
export const escapedPayload: Rule = {
  id: 'encoding/escaped-text',
  title: 'Escape-encoded hidden text',
  family: 'encoding',
  severity: 'high',
  description:
    'Long runs of unicode, hex, decimal or percent escapes that reconstruct readable instruction text.',
  message: 'A run of character escapes that reassembles into readable text.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];

    const decoders: {
      re: RegExp;
      decode: (raw: string) => string;
      label: string;
    }[] = [
      {
        re: /(?:\\u\{?[0-9a-fA-F]{2,6}\}?){8,}/g,
        decode: (raw) =>
          (raw.match(/\\u\{?([0-9a-fA-F]{2,6})\}?/g) ?? [])
            .map((piece) => safeFromCodePoint(parseInt(piece.replace(/\\u\{?|\}/g, ''), 16)))
            .join(''),
        label: 'unicode escapes',
      },
      {
        re: /(?:\\x[0-9a-fA-F]{2}){8,}/g,
        decode: (raw) =>
          (raw.match(/\\x([0-9a-fA-F]{2})/g) ?? [])
            .map((piece) => String.fromCharCode(parseInt(piece.slice(2), 16)))
            .join(''),
        label: 'hex escapes',
      },
      {
        re: /(?:%[0-9a-fA-F]{2}){10,}/g,
        decode: (raw) => {
          try {
            return decodeURIComponent(raw);
          } catch {
            return '';
          }
        },
        label: 'percent-encoding',
      },
      {
        re: /String\.fromCharCode\(\s*(?:\d{1,3}\s*,\s*){7,}\d{1,3}\s*\)/g,
        decode: (raw) =>
          (raw.match(/\d{1,3}/g) ?? []).map((n) => String.fromCharCode(Number(n))).join(''),
        label: 'String.fromCharCode',
      },
      {
        re: /\b(?:0x[0-9a-fA-F]{2}\s*,\s*){9,}0x[0-9a-fA-F]{2}\b/g,
        decode: (raw) =>
          (raw.match(/0x([0-9a-fA-F]{2})/g) ?? [])
            .map((piece) => String.fromCharCode(parseInt(piece.slice(2), 16)))
            .join(''),
        label: 'a hex byte array',
      },
    ];

    for (const { re, decode, label } of decoders) {
      for (const match of execAll(re, ctx.text)) {
        if (match[0].length > MAX_DECODE_LENGTH) continue;
        const decoded = decode(match[0]);
        if (decoded.length < 8) continue;

        const injection = DECODED_INJECTION_RE.test(decoded);
        const command = DECODED_COMMAND_RE.test(decoded);
        const prose = looksLikeProse(decoded);
        if (!injection && !command && !prose) continue;

        findings.push({
          ruleId: 'encoding/escaped-text',
          index: match.index,
          match: match[0].slice(0, 120),
          severity: injection ? 'critical' : command ? 'high' : 'medium',
          message: injection
            ? `Text hidden in ${label} that decodes to prompt-injection language: "${truncate(decoded)}"`
            : command
              ? `Commands hidden in ${label}: "${truncate(decoded)}"`
              : `Readable English hidden in ${label}: "${truncate(decoded)}". Encoding plain text is a way to keep it out of a reviewer's eye.`,
          detail: { decoded: truncate(decoded, 500), encoding: label },
        });
      }
    }

    return findings;
  },
};

/** Runtime decode-and-execute. Not injection itself, but it travels with it. */
export const dynamicDecode: Rule = {
  id: 'encoding/decode-and-execute',
  title: 'Decode chained into execution',
  family: 'encoding',
  severity: 'high',
  description:
    'A decode call (atob, Buffer.from base64, codecs.decode) feeding directly into eval or a shell.',
  message:
    'Decoded data flows straight into an evaluator. This is how an obfuscated payload gets to run without ever appearing in the source.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];
    const re =
      /(?:eval|Function|exec|execSync|spawnSync|system|Invoke-Expression|iex)\s*\(?[^;\n]{0,80}(?:atob|Buffer\.from\s*\([^)]*base64|b64decode|base64\.b64decode|codecs\.decode|FromBase64String)/gi;
    const reversed =
      /(?:atob|Buffer\.from\s*\([^)]*base64|b64decode|base64\.b64decode|FromBase64String)[^;\n]{0,80}(?:eval|new\s+Function|exec|execSync|Invoke-Expression)\s*\(/gi;

    for (const pattern of [re, reversed]) {
      for (const match of execAll(pattern, ctx.text)) {
        findings.push({
          ruleId: 'encoding/decode-and-execute',
          index: match.index,
          match: match[0],
        });
      }
    }

    return findings;
  },
};

export const encodingRules: Rule[] = [base64Payload, escapedPayload, dynamicDecode];
