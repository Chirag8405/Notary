import type { Decision, Reason } from "@notary/schema";

/**
 * Plain words for the monitor's technical output. The technical names stay available (as a
 * tooltip or in the Trust X-ray); the guided demo and the approval dialog show these instead.
 */

type Verdict = Decision["verdict"];
type Code = Reason["code"];
type Check = Reason["check"];

export interface VerdictText {
  /** Short label for a badge. */
  label: string;
  /** One sentence for a timeline row. */
  sentence: string;
  tone: "safe" | "warn" | "stop";
}

export const VERDICT_TEXT: Readonly<Record<Verdict, VerdictText>> = {
  ALLOW: { label: "Allowed", sentence: "NOTARY let this action through.", tone: "safe" },
  ESCALATE: {
    label: "Needs your approval",
    sentence: "NOTARY paused this action and is asking you.",
    tone: "warn",
  },
  BLOCK: { label: "Stopped", sentence: "NOTARY stopped this action.", tone: "stop" },
};

export const CHECK_TEXT: Readonly<Record<Check, string>> = {
  scope: "Is this something you asked for?",
  irreversibility: "Can it be undone?",
  origin: "Where did the details come from?",
  corroboration: "Do you already know these details?",
  confidentiality: "Would private data leave?",
  budget: "Is it within your limits?",
};

export const REASON_TEXT: Readonly<Record<Code, string>> = {
  STEP_PASS: "This check passed.",
  READ_ONLY_UNGATED: "It only reads data, so it is safe to run.",
  SCOPE_TOOL_NOT_IN_CONTRACT: "You did not ask the agent to use this tool.",
  SCOPE_MANIFEST_MISMATCH: "The tool changed since you approved it.",
  SCOPE_PARAM_NOT_IN_CONTRACT: "The action carries a detail you did not ask for.",
  IRREVERSIBLE_NOT_AUTHORIZED: "This cannot be undone and you did not authorize it.",
  ORIGIN_UNTRUSTED: "The details came from content the agent read, not from you.",
  ORIGIN_UNSOURCED: "The details have no known source.",
  ORIGIN_LITERAL_MISMATCH: "The details do not match what you typed.",
  ORIGIN_SOURCE_MISMATCH: "The details came from a source you did not point to.",
  LEDGER_EXACT_MATCH: "It matches something you already know and trust.",
  LEDGER_LOOKALIKE: "It looks almost like something you know, but is not the same.",
  LEDGER_NOVEL_ESCALATE: "This is new to you: you have not used it before.",
  LEDGER_NOT_FOUND: "This is not among the things you know.",
  CONF_READER_VIOLATION: "Private data would be sent to someone who should not see it.",
  CONF_URL_NOT_ALLOWED: "The address it would contact is not allowed.",
  CONF_CONTEXT_ESCALATE:
    "The agent wrote this after reading private data, and the recipient may not see that data.",
  BUDGET_AMOUNT: "The amount is over your limit.",
  BUDGET_SENDS: "It would send more messages than your limit.",
  BUDGET_EGRESS_BYTES: "It would send more data than your limit.",
  BUDGET_APPROVALS_EXHAUSTED: "You have no approvals left for this task.",
  BUDGET_ESCALATIONS_EXHAUSTED: "The agent has already asked you too many times in this task.",
};

/** The sentence for a reason code given as plain text (a log line); null for a code not known. */
export function reasonTextFor(code: string): string | null {
  return Object.hasOwn(REASON_TEXT, code) ? REASON_TEXT[code as Code] : null;
}

export function verdictText(verdict: Verdict): VerdictText {
  return VERDICT_TEXT[verdict];
}

export function reasonText(code: Code): string {
  return REASON_TEXT[code];
}

/** The reason that decided the call: the first one that did not pass, else the first. */
export function decidingReason(decision: Decision): Reason | null {
  return (
    decision.reasons.find((reason) => reason.outcome !== "pass") ?? decision.reasons[0] ?? null
  );
}

/** One sentence saying why the call got its verdict. */
export function explainDecision(decision: Decision): string {
  const reason = decidingReason(decision);
  return reason === null ? VERDICT_TEXT[decision.verdict].sentence : REASON_TEXT[reason.code];
}

/** Tool names as a person says them. */
const TOOL_TEXT: Readonly<Record<string, string>> = {
  pay_bill: "Pay a bill",
  send_email: "Send an email",
  read_inbox: "Read the inbox",
  read_file: "Read a file",
  delete_email: "Delete an email",
  add_contact: "Add a contact",
};

export function toolText(tool: string): string {
  return TOOL_TEXT[tool] ?? tool.replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
}

/** Parameter names as a person says them. */
const PARAM_TEXT: Readonly<Record<string, string>> = {
  iban: "Account (IBAN)",
  amount: "Amount",
  to: "Recipient",
  recipient: "Recipient",
  subject: "Subject",
  body: "Message",
};

export function paramText(param: string): string {
  return PARAM_TEXT[param] ?? param.replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
}
