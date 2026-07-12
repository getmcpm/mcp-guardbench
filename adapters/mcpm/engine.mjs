#!/usr/bin/env node

// src/guard/patterns.ts
function* stringLeaves(node, depth = 0, maxDepth = 32) {
  if (depth > maxDepth) return;
  if (typeof node === "string") {
    yield node;
    return;
  }
  if (Array.isArray(node)) {
    for (const child of node) yield* stringLeaves(child, depth + 1, maxDepth);
    return;
  }
  if (node !== null && typeof node === "object") {
    for (const value of Object.values(node)) yield* stringLeaves(value, depth + 1, maxDepth);
  }
}
function unhandledTarget(_) {
  return null;
}
function targetSubtree(msg, target) {
  switch (target) {
    case "tool_response": {
      const error = msg.error ?? null;
      if ("result" in msg) {
        const result = msg.result;
        return [result?.content ?? null, result?.structuredContent ?? null, error];
      }
      return error;
    }
    case "tool_call_args": {
      if ("method" in msg && msg.method === "tools/call" && "params" in msg) {
        const params = msg.params;
        return params?.arguments ?? null;
      }
      return null;
    }
    case "tool_description": {
      if ("result" in msg) {
        const result = msg.result;
        const tools = result?.tools;
        if (!tools) return null;
        return tools.map((t) => [t.description ?? "", t.title ?? "", t.inputSchema ?? null]);
      }
      return null;
    }
    case "tool_annotations": {
      if ("result" in msg) {
        const result = msg.result;
        const tools = result?.tools;
        if (!tools) return null;
        return tools.map((t) => t.annotations ?? null);
      }
      return null;
    }
    case "resource_content": {
      if ("result" in msg) {
        const result = msg.result;
        const contents = result?.contents;
        if (!Array.isArray(contents)) return null;
        return contents.map((c) => c.text ?? null);
      }
      return null;
    }
    case "prompt_content": {
      if ("result" in msg) {
        const result = msg.result;
        const messages = result?.messages;
        if (!Array.isArray(messages)) return null;
        return messages.map((m) => m.content ?? null);
      }
      return null;
    }
    case "initialize_instructions": {
      if ("result" in msg) {
        const result = msg.result;
        if (typeof result?.protocolVersion !== "string") return null;
        return [result.instructions ?? null, result.serverInfo ?? null];
      }
      return null;
    }
    case "sampling_prompt":
      return null;
    default:
      return unhandledTarget(target);
  }
}
var MAX_EXCERPT = 200;
function truncate(s) {
  return s.length > MAX_EXCERPT ? `${s.slice(0, MAX_EXCERPT)}\u2026` : s;
}
var MATCH_SEGMENT_CAP = 32 * 1024;
var PATTERN_BREAKERS = /[­​-‏‪-‮⁠-⁯﻿]|[\u{E0000}-\u{E007F}]/gu;
var CONFUSABLES = {
  // ── Cyrillic → Latin ──
  "\u0430": "a",
  "\u0410": "A",
  // а А
  "\u0435": "e",
  "\u0415": "E",
  // е Е
  "\u043E": "o",
  "\u041E": "O",
  // о О
  "\u0440": "p",
  "\u0420": "P",
  // р Р
  "\u0441": "c",
  "\u0421": "C",
  // с С
  "\u0443": "y",
  "\u0423": "Y",
  // у У
  "\u0445": "x",
  "\u0425": "X",
  // х Х
  "\u0456": "i",
  "\u0406": "I",
  // і І
  "\u0458": "j",
  "\u0408": "J",
  // ј Ј
  "\u0501": "d",
  // ԁ
  "\u051B": "q",
  // ԛ
  "\u0455": "s",
  "\u0405": "S",
  // ѕ Ѕ
  "\u04BB": "h",
  // һ
  // ── Greek → Latin ──
  "\u03BF": "o",
  "\u039F": "O",
  // ο Ο
  "\u03B1": "a",
  "\u0391": "A",
  // α Α
  "\u03B5": "e",
  "\u0395": "E",
  // ε Ε
  "\u03B9": "i",
  "\u0399": "I",
  // ι Ι
  "\u03BD": "v",
  "\u039D": "N",
  // ν Ν
  "\u03C1": "p",
  "\u03A1": "P",
  // ρ Ρ
  "\u03C4": "t",
  "\u03A4": "T",
  // τ Τ
  "\u03C5": "u",
  "\u03A5": "Y",
  // υ Υ
  "\u03C7": "x",
  "\u03A7": "X",
  // χ Χ
  "\u03BA": "k",
  "\u039A": "K",
  // κ Κ
  "\u03B7": "n",
  "\u0397": "H"
  // η Η
};
function foldConfusables(s) {
  let out = "";
  for (const ch of s) out += CONFUSABLES[ch] ?? ch;
  return out;
}
function normalizeSegment(segment) {
  return foldConfusables(segment.normalize("NFKC").replace(PATTERN_BREAKERS, ""));
}
function normalizeForMatch(leaf) {
  if (leaf.length <= MATCH_SEGMENT_CAP) {
    return normalizeSegment(leaf);
  }
  const head = normalizeSegment(leaf.slice(0, MATCH_SEGMENT_CAP));
  const tail = normalizeSegment(leaf.slice(-MATCH_SEGMENT_CAP));
  return `${head}
${tail}`;
}
function inspectAgainstSignatures(leaf, signatures, target) {
  const normalized = normalizeForMatch(leaf);
  const findings = [];
  for (const sig of signatures) {
    if (sig.target !== target) continue;
    for (const pattern of sig.patterns) {
      pattern.lastIndex = 0;
      const match = pattern.exec(normalized);
      if (match) {
        findings.push({
          signature_id: sig.id,
          category: sig.category,
          severity: sig.severity,
          target: sig.target,
          matched_text_excerpt: truncate(match[0]),
          remediation: sig.remediation
        });
        break;
      }
    }
  }
  return findings;
}
var HIDDEN_CHAR_TARGETS = /* @__PURE__ */ new Set([
  "tool_description",
  "tool_annotations",
  // initialize.instructions is block-capable PRE-INVOCATION context (H1). An
  // invisible separator embedded there to obfuscate keywords would otherwise go
  // unreported, so it's in scope. resource_content / prompt_content stay OUT of
  // scope — invisible chars in fetched files/emails are common and benign. (H2)
  "initialize_instructions"
]);
var HIDDEN_CHAR_CLASS = /[\u200b-\u200f\u2060-\u2064\ufeff\u00ad\u202a-\u202e\u2066-\u2069]|[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]|[\u0080-\u009f]|[\u{E0000}-\u{E007F}]/gu;
function classifyHiddenChar(ch) {
  const cp = ch.codePointAt(0) ?? 0;
  const hex = `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
  let kind;
  if (cp === 27) kind = "ANSI-ESC";
  else if (cp === 65279 || cp === 8288) kind = "zero-width";
  else if (cp === 8203 || cp === 8204 || cp === 8205) kind = "zero-width";
  else if (cp >= 8289 && cp <= 8292) kind = "invisible-math";
  else if (cp === 173) kind = "soft-hyphen";
  else if (cp === 8206 || cp === 8207) kind = "bidi-control";
  else if (cp >= 8234 && cp <= 8238 || cp >= 8294 && cp <= 8297) kind = "bidi-control";
  else if (cp >= 917504 && cp <= 917631) kind = "unicode-tag";
  else if (cp >= 128 && cp <= 159) kind = "C1-control";
  else kind = "control";
  return `${kind} (${hex})`;
}
function isEmojiJoinComponent(cp) {
  if (cp === void 0) return false;
  if (cp === 65039) return true;
  if (cp >= 127995 && cp <= 127999) return true;
  return new RegExp("\\p{Extended_Pictographic}", "u").test(String.fromCodePoint(cp));
}
function detectHiddenChars(leaf, target) {
  const scanned = leaf.length <= MATCH_SEGMENT_CAP * 2 ? leaf : leaf.slice(0, MATCH_SEGMENT_CAP) + leaf.slice(-MATCH_SEGMENT_CAP);
  HIDDEN_CHAR_CLASS.lastIndex = 0;
  for (let m = HIDDEN_CHAR_CLASS.exec(scanned); m !== null; m = HIDDEN_CHAR_CLASS.exec(scanned)) {
    if (m[0].codePointAt(0) === 8205) {
      const before = codePointBefore(scanned, m.index);
      const after = scanned.codePointAt(m.index + 1);
      if (isEmojiJoinComponent(before) && isEmojiJoinComponent(after)) continue;
    }
    return [
      {
        signature_id: "hidden-chars-in-metadata",
        category: "OWASP-MCP-1",
        severity: "high",
        target,
        matched_text_excerpt: `${classifyHiddenChar(m[0])} in ${target}`,
        remediation: "Tool metadata contains invisible/control characters that hide content from human review (tool-poisoning indicator). Inspect the server's source; if legitimate (rare), mute via `mcpm guard mute hidden-chars-in-metadata`."
      }
    ];
  }
  return [];
}
function codePointBefore(s, index) {
  if (index <= 0) return void 0;
  const prev = s.charCodeAt(index - 1);
  if (prev >= 56320 && prev <= 57343 && index >= 2) {
    return s.codePointAt(index - 2);
  }
  return prev;
}
var ACTION_RANK = { pass: 0, warn: 1, block: 2 };
var WARN_ONLY_TARGETS = /* @__PURE__ */ new Set([
  "resource_content",
  "prompt_content"
]);
function severityToAction(sev) {
  if (sev === "critical") return "block";
  if (sev === "high") return "warn";
  return "pass";
}
function defaultActionForFinding(f) {
  const native = severityToAction(f.severity);
  if (WARN_ONLY_TARGETS.has(f.target) && ACTION_RANK[native] > ACTION_RANK.warn) {
    return "warn";
  }
  return native;
}
function inspectMessage(msg, signatures) {
  const targets = [
    "tool_response",
    "tool_call_args",
    "tool_description",
    "tool_annotations",
    "resource_content",
    "prompt_content",
    "initialize_instructions"
  ];
  const findings = [];
  for (const target of targets) {
    const subtree = targetSubtree(msg, target);
    if (subtree === null || subtree === void 0) continue;
    for (const leaf of stringLeaves(subtree)) {
      if (HIDDEN_CHAR_TARGETS.has(target)) {
        findings.push(...detectHiddenChars(leaf, target));
      }
      findings.push(...inspectAgainstSignatures(leaf, signatures, target));
    }
  }
  if (findings.length === 0) return { action: "pass", findings: [] };
  const action = findings.reduce((acc, f) => {
    const a = defaultActionForFinding(f);
    return ACTION_RANK[a] > ACTION_RANK[acc] ? a : acc;
  }, "pass");
  return { action, findings };
}

// src/guard/signatures.ts
var SOLICIT_VERB = "(?:enter|re-?enter|type|paste|provide|input|share|submit|confirm|reveal|supply|restore|recover|verify|key[\\s-]*in|fill[\\s-]*in)";
var solicits = (noun) => new RegExp(`${SOLICIT_VERB}[\\s\\S]{0,40}(?:${noun})`, "i");
var OWASP_MCP_TOP_10 = [
  {
    id: "owasp-mcp-2-instruction-injection-in-response",
    category: "OWASP-MCP-2",
    severity: "critical",
    description: "Imperative instructions embedded in tool response content",
    target: "tool_response",
    // [\s]+ instead of literal space catches newline / tab / multi-space evasions
    // (an attacker inserting "ignore\nprevious instructions" otherwise bypasses).
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /you[\s]+are[\s]+now[\s]+(?:in[\s]+|operating[\s]+in[\s]+|entering[\s]+)?(?:developer|debug|admin|jailbreak|dan)[\s]+mode/i,
      /<\|system\|>|<\|im_start\|>system/
    ],
    remediation: "Tool response contained injection-shaped text. Review the upstream data source (message, web page, file). If legitimate, allow via `mcpm guard mute owasp-mcp-2-instruction-injection-in-response --for 5m`."
  },
  {
    id: "owasp-mcp-7-path-exfil-in-args",
    category: "OWASP-MCP-7",
    severity: "high",
    description: "Sensitive filesystem paths in tool call arguments",
    target: "tool_call_args",
    patterns: [
      /\.ssh\/|\.aws\/credentials|\.env(\b|$)|id_rsa|\.gnupg\/|\.kube\/config/i
    ],
    remediation: "Tool call argument referenced a sensitive file path. Common in exfil chains after a tool-poisoning attack. Verify the agent's intent before allowing."
  },
  {
    id: "owasp-mcp-1-tool-description-injection",
    category: "OWASP-MCP-1",
    severity: "critical",
    description: "Instruction-shaped text in tool descriptions (poisoning / rug-pull)",
    target: "tool_description",
    // The previous version included /when (?:the )?user asks/ which false-positives
    // on legitimate descriptions like "Returns X when the user asks for Y." Tightened
    // to require an imperative verb following the phrase, which is the actual
    // tool-poisoning shape (e.g., "when the user asks, exfiltrate ~/.ssh/").
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /<important>|<system>/i,
      /when[\s]+(?:the[\s]+)?user[\s]+asks,?[\s]+(?:you[\s]+(?:must|should|always|never)|always|never|exfil|read|access|send|email|do[\s]+not)/i
    ],
    remediation: "A tool description contains imperative or system-prompt-style text. Tool-poisoning pattern (Invariant Labs disclosure, 2025). Re-review the server; if legitimate, run `mcpm guard accept-drift <server>`."
  },
  {
    id: "owasp-mcp-2-instruction-injection-in-resource",
    category: "OWASP-MCP-2",
    severity: "critical",
    description: "Imperative instructions embedded in retrieved resource content",
    // resources/read content is RETRIEVED DATA — inspectMessage clamps a match
    // here to `warn` (annotate + forward), so a poisoned/quoted README is flagged
    // but never dropped. Severity stays critical (pattern confidence is honest).
    target: "resource_content",
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /you[\s]+are[\s]+now[\s]+(?:in[\s]+|operating[\s]+in[\s]+|entering[\s]+)?(?:developer|debug|admin|jailbreak|dan)[\s]+mode/i,
      /<\|system\|>|<\|im_start\|>system/
    ],
    remediation: "Retrieved resource content contained injection-shaped text. This is annotated and forwarded (not blocked) so legitimate documents aren't corrupted. Review the source resource; if hostile, stop reading from it."
  },
  {
    id: "owasp-mcp-2-instruction-injection-in-prompt",
    category: "OWASP-MCP-2",
    severity: "critical",
    description: "Imperative instructions embedded in a server-provided prompt",
    // prompts/get content is RETRIEVED DATA — warn-only via the inspectMessage clamp.
    target: "prompt_content",
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /you[\s]+are[\s]+now[\s]+(?:in[\s]+|operating[\s]+in[\s]+|entering[\s]+)?(?:developer|debug|admin|jailbreak|dan)[\s]+mode/i,
      /<\|system\|>|<\|im_start\|>system/
    ],
    remediation: "A server-provided prompt template contained injection-shaped text. Annotated and forwarded (not blocked). Review the prompt's source server."
  },
  {
    id: "owasp-mcp-1-initialize-instruction-injection",
    category: "OWASP-MCP-1",
    severity: "critical",
    description: "Instruction-shaped text in initialize instructions / serverInfo (line-jumping)",
    // initialize instructions + serverInfo are PRE-INVOCATION CONTEXT injected
    // into the agent before any tool call — block-capable (T2 line-jumping).
    target: "initialize_instructions",
    // Use genuine prompt-delimiter tokens (<|system|>, <|im_start|>system) like the
    // resource/prompt signatures — NOT a bare `<important>`/`<system>` tag. This
    // carrier is block-capable, so a loose emphasis tag in legitimate instruction
    // prose would hard-fail the server connection with an opaque JSON-RPC error.
    // (security: FP-2 over-block)
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /<\|system\|>|<\|im_start\|>system/,
      /you[\s]+are[\s]+now[\s]+(?:in[\s]+|operating[\s]+in[\s]+|entering[\s]+)?(?:developer|debug|admin|jailbreak|dan)[\s]+mode/i
    ],
    remediation: "A server's initialize instructions/serverInfo contain imperative or system-prompt-style text \u2014 a line-jumping attack that injects context before any tool runs. Re-review the server; if legitimate, run `mcpm guard accept-drift <server>`."
  },
  {
    // F6 credential-phishing wedge. Targets `prompt_content` so it rides the
    // existing server-initiated scan path (run-inner.ts inspectServerInitiated
    // wraps a sampling/elicitation request into a synthetic prompts/get frame and
    // RE-TAGS findings to the block-capable `sampling_prompt` carrier). Net effect:
    // a server that PROMPTS the user (via elicitation/create or sampling) to enter a
    // wallet secret is BLOCKED with the error routed back to the server; the same
    // string in a passive prompts/get template is warn-only (retrieved data).
    //
    // Every pattern is built with solicits() (imperative cue + credential noun) — see
    // the SOLICIT_VERB note above for why mention-vs-ask anchoring is load-bearing.
    //
    // FP discipline: only credential types no legitimate MCP server ever solicits are
    // in the block tier. Generic api-key / password / token / access-token /
    // client-secret / bearer are DELIBERATELY EXCLUDED — a server asking for ITS OWN
    // config secret during first-run setup is the single most common (and
    // spec-intended) elicitation, so hard-blocking it would break the feature.
    // "private key" is additionally anchored to crypto-wallet co-occurrence so an
    // SSH/cert/GPG key-manager that elicits "paste your private key" to import a key
    // is NOT blocked (bare "private key" never matches). "mnemonic" requires crypto
    // context too (an assembly/flashcard server legitimately says "enter the
    // mnemonic"). The confusable fold is partial (CONFUSABLES covers s/e/d/o/p/c…
    // but not every anchor letter, e.g. m), so this catches the literal/homoglyph
    // string, not semantic rephrasing (V2 LLM-judge). OTP / verification-code is
    // intentionally NOT here: a legit device-flow / email-verification server
    // elicits "enter the code we sent you" during its own pairing and the relay
    // can't tell self-pairing from a third-party-login relay without provenance.
    id: "credential-phishing-wallet-solicitation",
    category: "MCP-CREDENTIAL-PHISHING",
    severity: "critical",
    description: "Server-initiated prompt soliciting a crypto-wallet seed/recovery phrase, mnemonic, or wallet private key (drainer phishing)",
    target: "prompt_content",
    patterns: [
      solicits("seed[\\s-]*(?:phrase|words)"),
      solicits("recovery[\\s-]*(?:phrase|seed|words)"),
      solicits("\\bbip[\\s-]?0?39\\b"),
      // mnemonic must ALSO carry crypto/wallet/phrase context (either order) — bare
      // "mnemonic" is legitimate (assembly opcode, memory aid, flashcard). (review HIGH)
      solicits("(?:wallet|crypto|seed|recovery|metamask|ledger|trezor)[\\s\\S]{0,25}mnemonic"),
      solicits("mnemonic[\\s\\S]{0,25}(?:phrase|words?|seed|recovery|wallet|crypto)"),
      // "private key" ONLY with a crypto-wallet cue within a bounded window (either
      // order). Bare "private key" (SSH / TLS cert / GPG / JWT signing) never matches
      // — those are legitimate key-import elicitations. (critique CRITICAL #1)
      solicits(
        "(?:wallet|crypto(?:currency)?|seed|mnemonic|recovery|metamask|ledger|trezor|bitcoin|ethereum|solana|phantom)[\\s\\S]{0,40}private[\\s-]*key"
      ),
      solicits(
        "private[\\s-]*key[\\s\\S]{0,40}(?:wallet|crypto(?:currency)?|seed|mnemonic|recovery|metamask|ledger|trezor|bitcoin|ethereum|solana|phantom)"
      )
    ],
    remediation: "A server prompted the user to enter a crypto-wallet seed/recovery phrase, mnemonic, or wallet private key. No legitimate MCP server asks for these \u2014 it is a wallet-drainer phishing pattern. The request was blocked and a JSON-RPC error returned to the server. If you are certain this is legitimate, mute via `mcpm guard mute credential-phishing-wallet-solicitation`."
  },
  {
    // F6 financial-secret tier — same solicits() anchoring + prompt_content/
    // sampling_prompt path as the wallet signature above. Block tier = card CVV/CVC,
    // a solicited SSN, and a card/bank/ATM PIN. PIN REQUIRES a financial qualifier
    // (card/bank/atm/debit/credit) so "pin this message" never matches (critique
    // MAJOR #3); CVC requires a card cue so a bare acronym ("CVC Capital") doesn't
    // fire. The SSN acronym is gated by solicits() so "map the ssn field" / "the SSN
    // column" — common field-name prose — does NOT block; only an actual ask does
    // (review HIGH). SSN is the one block-tier item a narrow set of legitimate
    // servers (tax / payroll / healthcare intake) may genuinely need, so the
    // remediation points those users at the mute path.
    id: "credential-phishing-financial-solicitation",
    category: "MCP-CREDENTIAL-PHISHING",
    severity: "critical",
    description: "Server-initiated prompt soliciting a card CVV/CVC, SSN, or card/bank PIN (financial phishing)",
    target: "prompt_content",
    patterns: [
      solicits("\\bcvv2?\\b"),
      solicits("\\bcvc\\b[\\s\\S]{0,20}card|card[\\s\\S]{0,20}\\bcvc\\b"),
      solicits("card[\\s-]*(?:security|verification)[\\s-]*(?:code|value|number)"),
      solicits("social[\\s-]*security[\\s-]*number"),
      solicits("\\bssn\\b"),
      solicits("(?:card|bank|atm|debit|credit)[\\s-]*(?:card[\\s-]*)?pin\\b")
    ],
    remediation: "A server prompted the user to enter a card CVV/CVC, Social Security Number, or card/bank PIN. Almost no legitimate MCP server solicits these via a prompt \u2014 it is a phishing pattern. The request was blocked and a JSON-RPC error returned to the server. Tax-filing, payroll, or healthcare-intake servers are the rare exception that may legitimately elicit an SSN; if you trust such a server, mute via `mcpm guard mute credential-phishing-financial-solicitation`."
  },
  {
    // F5 — STRUCTURAL exfil-param detector. The finding is emitted by
    // detectExfilParams (a property-KEY walker over tools/list inputSchemas, NOT a
    // content regex), so this catalog entry carries NO patterns. It exists only so
    // the id is recognized by `guard mute exfil-param-in-schema`, `guard
    // list-signatures`, and policy signature_overrides — all of which enumerate
    // OWASP_MCP_TOP_10 ids. `inspectAgainstSignatures` safely no-ops on an empty
    // patterns array (its inner pattern loop never runs). (The
    // hidden-chars-in-metadata entry below uses this same empty-patterns pattern.)
    id: "exfil-param-in-schema",
    category: "OWASP-MCP-1",
    severity: "critical",
    description: "Tool input schema declares a context-exfiltration sigil parameter (e.g. _system_prompt_) the model auto-fills",
    target: "tool_description",
    patterns: [],
    remediation: "A tool's input schema declares a parameter named like a context-exfiltration sigil (e.g. `_system_prompt_`) that the model would silently auto-fill \u2014 a zero-interaction prompt leak. No legitimate tool names a parameter this way. The server's whole tools/list was blocked. Tripwire for the documented underscore-sigil convention; a renamed param evades it. If trusted, mute via `mcpm guard mute exfil-param-in-schema`."
  },
  {
    // hidden-chars-in-metadata — the H2 PRESENCE detector (detectHiddenChars in
    // patterns.ts) emits this finding INLINE from a codepoint scan of raw metadata
    // leaves, NOT a content regex, so like exfil-param-in-schema above it carries NO
    // patterns. The entry exists only so the id is recognized by `guard mute
    // hidden-chars-in-metadata` (the block message instructs exactly that),
    // `guard list-signatures`, and policy signature_overrides — all of which
    // enumerate OWASP_MCP_TOP_10 ids. `inspectAgainstSignatures` no-ops on the empty
    // patterns array. Keep `patterns: []`: a regex here would double-fire alongside
    // the detectHiddenChars emission.
    id: "hidden-chars-in-metadata",
    category: "OWASP-MCP-1",
    severity: "high",
    description: "Invisible/control characters in tool metadata (description, title, inputSchema text, annotations) that hide content from human review",
    target: "tool_description",
    patterns: [],
    remediation: "Tool metadata contains invisible/control characters that hide content from human review (tool-poisoning indicator). Inspect the server's source; if legitimate (rare), mute via `mcpm guard mute hidden-chars-in-metadata`."
  }
];
export {
  OWASP_MCP_TOP_10,
  inspectMessage
};
//# sourceMappingURL=_eng.js.map