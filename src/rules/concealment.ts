/**
 * Layout-based concealment.
 *
 * Everything here exploits the same asymmetry: a renderer or a reviewer's eye
 * drops the content, and a plain-text parse does not. White text on a white
 * background, a `display:none` div, or a line padded out past column 400 are
 * all invisible in a pull request and perfectly legible to a model reading
 * the raw bytes.
 */

import type { FileContext, RawFinding, Rule } from '../types';
import { execAll, hasAgentNameNear, IMPERATIVE_RE } from './helpers';
import { patternRule } from './helpers';

/** Instruction-shaped text worth reporting once we know it is concealed. */
const INSTRUCTIONAL_RE =
  /\b(?:you\s+(?:must|should|are|will|need)|ignore|disregard|forget|do\s+not|don'?t|always|never|instruction|prompt|assistant|system|AI|LLM|agent|model|task|safe|approved|verified)\b/i;

export const hiddenMarkup: Rule = {
  id: 'concealment/hidden-markup',
  title: 'Text hidden by markup',
  family: 'concealment',
  severity: 'high',
  description:
    'HTML that renders text invisible (display:none, zero font size, matching foreground and background) while leaving it in the source.',
  message:
    'Markup that hides this text from anyone viewing the rendered page, while leaving it fully readable to a model parsing the file.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];

    const hidingPatterns: { re: RegExp; why: string }[] = [
      {
        re: /<([a-z][\w-]*)\b[^>]*\bstyle\s*=\s*["'][^"']*\bdisplay\s*:\s*none[^"']*["'][^>]*>([\s\S]{4,600}?)<\/\1>/gi,
        why: 'display:none',
      },
      {
        re: /<([a-z][\w-]*)\b[^>]*\bstyle\s*=\s*["'][^"']*\bvisibility\s*:\s*hidden[^"']*["'][^>]*>([\s\S]{4,600}?)<\/\1>/gi,
        why: 'visibility:hidden',
      },
      {
        re: /<([a-z][\w-]*)\b[^>]*\bstyle\s*=\s*["'][^"']*\bfont-size\s*:\s*0(?:\.0+)?(?:px|em|rem|%)?[^"']*["'][^>]*>([\s\S]{4,600}?)<\/\1>/gi,
        why: 'a zero font size',
      },
      {
        re: /<([a-z][\w-]*)\b[^>]*\bstyle\s*=\s*["'][^"']*\bcolor\s*:\s*(?:#f{3,8}\b|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)[^"']*["'][^>]*>([\s\S]{4,600}?)<\/\1>/gi,
        why: 'white text',
      },
      {
        re: /<([a-z][\w-]*)\b[^>]*\bstyle\s*=\s*["'][^"']*\bopacity\s*:\s*0(?:\.0+)?\s*[;"'][^>]*>([\s\S]{4,600}?)<\/\1>/gi,
        why: 'zero opacity',
      },
      {
        re: /<([a-z][\w-]*)\b[^>]*\bhidden\b[^>]*>([\s\S]{4,600}?)<\/\1>/gi,
        why: 'the hidden attribute',
      },
      {
        re: /<([a-z][\w-]*)\b[^>]*\baria-hidden\s*=\s*["']true["'][^>]*>([\s\S]{4,600}?)<\/\1>/gi,
        why: 'aria-hidden',
      },
    ];

    for (const { re, why } of hidingPatterns) {
      for (const match of execAll(re, ctx.text)) {
        const inner = (match[2] ?? '').replace(/<[^>]*>/g, ' ').trim();
        if (inner.length < 12) continue;
        if (!INSTRUCTIONAL_RE.test(inner)) continue;

        findings.push({
          ruleId: 'concealment/hidden-markup',
          index: match.index,
          match: match[0].slice(0, 200),
          severity: IMPERATIVE_RE.test(inner) ? 'critical' : 'high',
          message: `Instruction-shaped text hidden with ${why}. A reader of the rendered page never sees it; a model reading the source does.`,
          detail: { technique: why, hiddenText: inner.slice(0, 300) },
        });
      }
    }

    return findings;
  },
};

/**
 * Content shoved far off to the right, or buried under a wall of blank lines.
 * Both defeat a casual scroll through a diff.
 */
export const offscreenText: Rule = {
  id: 'concealment/offscreen-text',
  title: 'Text pushed out of view',
  family: 'concealment',
  severity: 'medium',
  description:
    'Content padded past the visible width of an editor, or separated from the rest of the file by a wall of blank lines.',
  message:
    'Content positioned where a reader will not scroll to it. Position means nothing to a model reading the file as one string.',
  scan(ctx: FileContext): RawFinding[] {
    const findings: RawFinding[] = [];

    // Text preceded by an enormous horizontal pad.
    for (const match of execAll(/^[^\S\n]{200,}(\S[^\n]{10,})/gm, ctx.text)) {
      const content = match[1] ?? '';
      if (!INSTRUCTIONAL_RE.test(content)) continue;
      findings.push({
        ruleId: 'concealment/offscreen-text',
        index: match.index + match[0].length - content.length,
        match: content.slice(0, 200),
        message:
          'Instruction-shaped text indented past 200 columns, well outside the visible width of a normal editor or diff view.',
        detail: { technique: 'horizontal padding' },
      });
    }

    // Text buried after a long run of blank lines.
    for (const match of execAll(/(?:[^\S\n]*\n){40,}([^\n]{10,})/g, ctx.text)) {
      const content = match[1] ?? '';
      if (!INSTRUCTIONAL_RE.test(content)) continue;
      findings.push({
        ruleId: 'concealment/offscreen-text',
        index: match.index + match[0].length - content.length,
        match: content.slice(0, 200),
        message:
          'Instruction-shaped text placed after 40+ blank lines, a common trick for hiding content below the fold of a file preview.',
        detail: { technique: 'vertical padding' },
      });
    }

    return findings;
  },
};

/**
 * Markdown-native hiding places: comment-reference syntax, image alt text, and
 * link titles. All of them vanish when rendered and all of them survive the
 * plain-text read an agent performs.
 */
export const markdownConcealment: Rule = patternRule({
  id: 'concealment/markdown-metadata',
  title: 'Instructions in non-rendered markdown',
  family: 'concealment',
  severity: 'high',
  description:
    'Instruction text placed in markdown constructs that do not render: comment references, image alt text and link titles.',
  message:
    'Instruction text tucked into markdown that never renders. Readers of the rendered file will not see it; an agent reading the raw file will.',
  proseOnly: false,
  patterns: [
    {
      re: /^\s*\[(?:\/\/|#|comment)\]\s*:\s*#?\s*\(([^)]{15,})\)/gim,
      confirm: (match) => INSTRUCTIONAL_RE.test(match[1] ?? ''),
      message:
        'A markdown comment reference (`[//]: # (...)`). It renders as nothing, which makes it a natural place to hide instructions.',
    },
    {
      re: /!\[([^\]]{25,})\]\([^)]*\)/g,
      severity: 'medium',
      confirm: (match, ctx) => {
        const alt = match[1] ?? '';
        return IMPERATIVE_RE.test(alt) && hasAgentNameNear(ctx.text, match.index, 200);
      },
      message:
        'Image alt text containing an instruction aimed at an AI agent. Alt text is invisible to sighted readers of the rendered page.',
    },
    {
      re: /\[[^\]]*\]\([^)\s]*\s+["']([^"']{25,})["']\)/g,
      severity: 'medium',
      confirm: (match) => IMPERATIVE_RE.test(match[1] ?? '') && INSTRUCTIONAL_RE.test(match[1] ?? ''),
      message:
        'A link title carrying instruction text. Titles only appear on hover, so this is effectively hidden in a rendered document.',
    },
  ],
});

/**
 * Informational, not an accusation: agent instruction files are read
 * automatically on the first turn, so their mere presence in third-party code
 * is something a reviewer should know about.
 */
export const agentConfigPresence: Rule = {
  id: 'agent-config/auto-loaded-instructions',
  title: 'Auto-loaded agent instruction file',
  family: 'agent-config',
  severity: 'info',
  description:
    'The repository ships a file that coding agents load as instructions without being asked.',
  message:
    'This file is read as instructions by coding agents before you ask them anything. Worth reading yourself before pointing an agent at this repository.',
  scan(ctx: FileContext): RawFinding[] {
    if (!ctx.isAgentInstructionFile) return [];
    return [
      {
        ruleId: 'agent-config/auto-loaded-instructions',
        index: 0,
        match: ctx.path,
        message: `\`${ctx.path}\` is loaded automatically as instructions by coding agents. Findings inside it carry more weight, and its contents deserve a read even when nothing else is flagged.`,
        detail: { path: ctx.path },
      },
    ];
  },
};

export const concealmentRules: Rule[] = [
  hiddenMarkup,
  offscreenText,
  markdownConcealment,
  agentConfigPresence,
];
