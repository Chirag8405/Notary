/**
 * The read token of a browser tab (#235).
 *
 * The tab makes one random token and keeps it for its lifetime. It goes on the tab's `cassette`
 * and `live` sockets (`?token=`) and on the pending-card list (`X-Notary-Token`), so the server
 * lists only the cards of this tab's sockets. It only lets the tab READ its list; answering a card
 * still needs the socket that owns it.
 *
 * A UUID is 36 characters of `[0-9a-f-]`, inside the 32 to 128 characters the server accepts. The
 * random source is a parameter so a test can count how often a token is made.
 */
export function newTabToken(random: () => string = () => crypto.randomUUID()): string {
  return random();
}
