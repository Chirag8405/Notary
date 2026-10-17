import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import createClient from "openapi-fetch";
import { describe, expect, it } from "vitest";

import type { paths } from "../src/generated/api";
import { getAnchor, getPendingEndorsements, listModes, type PendingList } from "../src/rest";

const events = JSON.parse(
  readFileSync(
    resolve(import.meta.dirname, "../../world/fixtures/streams/poisoned_bill.notary.json"),
    "utf8",
  ),
) as { type: string; endorsement?: unknown }[];
const endorsement = events.find((event) => event.type === "endorsement_requested")?.endorsement;

const PENDING = {
  pending: [
    {
      card_text: "Pay DE00ATTACKER0000000001?",
      endorsement,
      remaining_approvals: 2,
      run_id: "run-poisoned_bill-notary",
    },
  ],
} as unknown as PendingList;
const TOKEN = "123e4567-e89b-12d3-a456-426614174000";
const ANCHOR = { run_id: "run-poisoned_bill-notary", head: "a".repeat(64), length: 11 };

/** A client whose fetch answers with a fixed status and body, and records the request URLs. */
function stub(status: number, body: unknown) {
  const urls: string[] = [];
  const tokens: (string | null)[] = [];
  const client = createClient<paths>({
    baseUrl: "http://server.test",
    fetch: (request: Request) => {
      urls.push(new URL(request.url).pathname);
      tokens.push(request.headers.get("X-Notary-Token"));
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { "content-type": "application/json" },
        }),
      );
    },
  });
  return { client, urls, tokens };
}

describe("REST wrappers", () => {
  it("listModes unwraps the mode list [I4]", async () => {
    const { client, urls } = stub(200, { modes: ["golden", "cassette"] });
    expect(await listModes(client)).toEqual(["golden", "cassette"]);
    expect(urls).toEqual(["/runs/modes"]);
  });

  it("getPendingEndorsements unwraps the pending list and encodes the run id [I4]", async () => {
    const { client, urls } = stub(200, PENDING);
    expect(await getPendingEndorsements(client, "a b/c", TOKEN)).toEqual(PENDING);
    expect(urls).toEqual(["/runs/a%20b%2Fc/endorsements"]);
  });

  it("getPendingEndorsements sends the tab's token as X-Notary-Token and nowhere else [I4]", async () => {
    const { client, urls, tokens } = stub(200, { pending: [] });
    await getPendingEndorsements(client, "r", TOKEN);
    expect(tokens).toEqual([TOKEN]);
    expect(urls).toEqual(["/runs/r/endorsements"]); // not in the path or the query
  });

  it("getPendingEndorsements returns an empty list as is, and throws on an HTTP error [I4]", async () => {
    expect(await getPendingEndorsements(stub(200, { pending: [] }).client, "r", TOKEN)).toEqual({
      pending: [],
    });
    await expect(getPendingEndorsements(stub(500, {}).client, "r", TOKEN)).rejects.toThrow(
      /status 500/,
    );
  });

  it("getAnchor returns the anchor [I4]", async () => {
    const { client, urls } = stub(200, ANCHOR);
    expect(await getAnchor(client, "run-poisoned_bill-notary")).toEqual(ANCHOR);
    expect(urls).toEqual(["/runs/run-poisoned_bill-notary/anchor"]);
  });

  it("getAnchor returns null on a 404 [I4]", async () => {
    const { client } = stub(404, { detail: "no anchor for this run" });
    expect(await getAnchor(client, "r")).toBeNull();
  });

  it("throws an Error that names the status on any other failure [I4]", async () => {
    await expect(getAnchor(stub(500, { detail: "boom" }).client, "r")).rejects.toThrow(
      /status 500/,
    );
    await expect(getAnchor(stub(422, { detail: [] }).client, "r")).rejects.toThrow(/status 422/);
    await expect(listModes(stub(503, { detail: "down" }).client)).rejects.toThrow(/status 503/);
    await expect(
      getPendingEndorsements(stub(404, { detail: "no such run" }).client, "r", TOKEN),
    ).rejects.toThrow(/status 404/);
    await expect(getPendingEndorsements(stub(500, {}).client, "r", TOKEN)).rejects.toBeInstanceOf(
      Error,
    );
  });
});
