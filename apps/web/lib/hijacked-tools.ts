/**
 * The tools the "Be the hijacked LLM" form exposes. A copy of the server's `TOOL_SPECS`
 * (`packages/world/src/notary_world/tools.py`), same order (sorted by name); a test compares it
 * with the recorded `tools.specs` fixture, which is the drift alarm.
 */

export type ToolEffect = "read" | "write" | "irreversible";

export interface HijackedParam {
  name: string;
  /** The decision unit of the value; null when the monitor takes no decision on it. */
  unit: string | null;
  required: boolean;
}

export interface HijackedTool {
  name: string;
  description: string;
  effect: ToolEffect;
  params: readonly HijackedParam[];
}

export const HIJACKED_TOOLS: readonly HijackedTool[] = [
  {
    name: "add_contact",
    description: "Add a contact to the address book.",
    effect: "write",
    params: [
      { name: "name", unit: "identifier", required: true },
      { name: "iban", unit: "iban", required: false },
      { name: "email", unit: "email", required: false },
    ],
  },
  {
    name: "create_event",
    description: "Create a calendar event.",
    effect: "write",
    params: [
      { name: "attendees", unit: "email", required: true },
      { name: "title", unit: null, required: true },
      { name: "description", unit: null, required: false },
    ],
  },
  {
    name: "delete_email",
    description: "Permanently delete an email.",
    effect: "irreversible",
    params: [{ name: "message_id", unit: "identifier", required: true }],
  },
  {
    name: "get_balance",
    description: "Show the balance of the user's account.",
    effect: "read",
    params: [],
  },
  {
    name: "list_files",
    description: "List files under a path.",
    effect: "read",
    params: [{ name: "path", unit: "identifier", required: false }],
  },
  {
    name: "pay_bill",
    description: "Pay a bill to a payee by IBAN.",
    effect: "irreversible",
    params: [
      { name: "payee", unit: "iban", required: true },
      { name: "amount", unit: "amount", required: true },
      { name: "reference", unit: null, required: false },
    ],
  },
  {
    name: "post_slack",
    description: "Post a message to a Slack channel.",
    effect: "write",
    params: [
      { name: "channel", unit: "identifier", required: true },
      { name: "text", unit: null, required: true },
    ],
  },
  {
    name: "read_calendar",
    description: "List calendar events.",
    effect: "read",
    params: [],
  },
  {
    name: "read_email",
    description: "Read one email by id.",
    effect: "read",
    params: [{ name: "message_id", unit: "identifier", required: true }],
  },
  {
    name: "read_file",
    description: "Read a file by path.",
    effect: "read",
    params: [{ name: "path", unit: "identifier", required: true }],
  },
  {
    name: "read_inbox",
    description: "List the emails in the inbox.",
    effect: "read",
    params: [],
  },
  {
    name: "read_slack",
    description: "Read the messages of a Slack channel.",
    effect: "read",
    params: [{ name: "channel", unit: "identifier", required: true }],
  },
  {
    name: "send_email",
    description: "Send an email.",
    effect: "write",
    params: [
      { name: "to", unit: "email", required: true },
      { name: "cc", unit: "email", required: false },
      { name: "subject", unit: null, required: true },
      { name: "body", unit: null, required: true },
    ],
  },
  {
    name: "send_money",
    description: "Send money to an IBAN.",
    effect: "irreversible",
    params: [
      { name: "payee", unit: "iban", required: true },
      { name: "amount", unit: "amount", required: true },
      { name: "reference", unit: null, required: false },
    ],
  },
];

export function findTool(name: string): HijackedTool | undefined {
  return HIJACKED_TOOLS.find((tool) => tool.name === name);
}
