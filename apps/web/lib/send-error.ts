const CLOSED = "run socket is not open";

/** What to tell a person when their answer could not be sent. */
export function describeSendError(error: unknown): string {
  const message = error instanceof Error ? error.message : "could not send the answer";
  return message.includes(CLOSED)
    ? `The connection to the server closed, so your answer could not be sent (${CLOSED}). Press Run again to start over.`
    : message;
}
