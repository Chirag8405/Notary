import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { vi } from "vitest";

/** One recorded REST answer: the status and the JSON body the real server sent. */
export interface Recorded<T = unknown> {
  status: number;
  body: T;
}

export const FIXTURE_NAMES = [
  "poison.sample",
  "poison.cassette-miss",
  "attacks.list",
  "attack.A3",
  "attack.A13",
  "attack.B1",
  "hijacked.start",
  "hijacked.step.pay_attacker",
  "hijacked.step.send_email",
  "hijacked.step.read_inbox",
  "hijacked.state",
  "hijacked.legit.start",
  "hijacked.legit.step.pay_biller",
  "arena.seed0",
  "arena.cassette-miss",
  "tools.specs",
] as const;

export type FixtureName = (typeof FIXTURE_NAMES)[number];

const dir = resolve(import.meta.dirname, "fixtures/playground");

/** A recorded answer, parsed fresh on each call. Written by capture_playground_fixtures.py. */
export function fixture(name: FixtureName): Recorded {
  if (!FIXTURE_NAMES.includes(name)) throw new Error(`unknown fixture: ${name}`);
  return JSON.parse(readFileSync(resolve(dir, `${name}.json`), "utf8")) as Recorded;
}

export interface StubbedRequest {
  method: string;
  path: string;
  /** The parsed JSON body of the request, or undefined when it had none. */
  body: unknown;
}

/**
 * Stubs `fetch` for the playground routes. `reply` decides the answer from the request; returning
 * undefined answers 404 {"detail":"not stubbed"}. Read `calls` to see what was asked, in order.
 */
export function stubPlayground(reply: (request: StubbedRequest) => Recorded | undefined) {
  const calls: StubbedRequest[] = [];
  const fetchMock = vi.fn(async (input: Request | string | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const text = request.method === "GET" ? "" : await request.clone().text();
    const stubbed: StubbedRequest = {
      method: request.method,
      path: new URL(request.url).pathname,
      body: text === "" ? undefined : (JSON.parse(text) as unknown),
    };
    calls.push(stubbed);
    const answer = reply(stubbed) ?? { status: 404, body: { detail: "not stubbed" } };
    return new Response(JSON.stringify(answer.body), {
      status: answer.status,
      headers: { "content-type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}
