import { CommandSchema, type Command } from "@notary/schema";

/** Validate a client -> server command with the generated Zod schema and encode it as JSON. */
export function encodeCommand(command: Command): string {
  return JSON.stringify(CommandSchema.parse(command));
}
