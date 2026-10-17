import { EventSchema } from "@notary/schema";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import createClient from "openapi-fetch";
import { describe, expect, it } from "vitest";

import type { paths } from "../src/generated/api";
import {
  PlaygroundHttpError,
  getHijacked,
  listAttacks,
  poisonWorld,
  runAttack,
  startArena,
  startHijacked,
  submitHijackedCall,
  type ArenaStartBody,
  type AttackCase,
  type HijackedState,
  type HijackedToolCallBody,
  type PoisonWorldBody,
} from "../src/playground";

const world = resolve(import.meta.dirname, "../../world/fixtures");

function fixture(path: string): unknown {
  return JSON.parse(readFileSync(resolve(world, path), "utf8"));
}

const GOLDEN = EventSchema.array().parse(fixture("streams/poisoned_bill.notary.json"));
const POISON = fixture("commands/poison_world.json") as PoisonWorldBody;
const ARENA = fixture("commands/arena_start.json") as ArenaStartBody;
const HIJACKED_CALL = fixture("commands/hijacked_tool_call.json") as HijackedToolCallBody;
const ORACLE = { attacker_goal_reached: false, invariants: [], user_goal_achieved: true };

interface Recorded {
  method: string;
  path: string;
  body: unknown;
}

/** A client whose fetch answers with a fixed status and body, and records each request. */
function stub(status: number, body: unknown) {
  const requests: Recorded[] = [];
  const client = createClient<paths>({
    baseUrl: "http://server.test",
    fetch: async (request: Request) => {
      const text = await request.text();
      requests.push({
        method: request.method,
        path: new URL(request.url).pathname,
        body: text === "" ? undefined : (JSON.parse(text) as unknown),
      });
      return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    },
  });
  return { client, requests };
}

function poisonBody(events: readonly unknown[]) {
  return {
    scenario_id: "poisoned_bill",
    runs: [
      {
        lane: "notary",
        run_id: "run-poisoned_bill-notary",
        events,
        attacker_goal_reached: false,
        user_goal_achieved: false,
      },
    ],
  };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected the call to reject");
}

describe("playground helpers", () => {
  it("poisonWorld sends the command and validates events [I6]", async () => {
    const { client, requests } = stub(200, poisonBody(GOLDEN));
    const result = await poisonWorld(client, POISON);
    expect(requests).toEqual([{ method: "POST", path: "/playground/poison", body: POISON }]);
    expect(result.scenario_id).toBe("poisoned_bill");
    expect(result.runs[0]?.events).toHaveLength(GOLDEN.length);
    expect(() => EventSchema.array().parse(result.runs[0]?.events)).not.toThrow();
    expect(result.runs[0]?.lane).toBe("notary");
  });

  it("an invalid event rejects the whole call [I6]", async () => {
    const { client } = stub(200, poisonBody([...GOLDEN, { type: "nope" }]));
    const error = await rejection(poisonWorld(client, POISON));
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(PlaygroundHttpError);
    expect((error as Error).message).toBe("playground response has invalid events");
  });

  it("returns new objects on every call [I6]", async () => {
    const { client } = stub(200, poisonBody(GOLDEN));
    const first = await poisonWorld(client, POISON);
    const second = await poisonWorld(client, POISON);
    expect(first).not.toBe(second);
    expect(first.runs[0]?.events).not.toBe(second.runs[0]?.events);
    expect(first).toEqual(second);
  });

  it("501 cassette miss [A3]", async () => {
    const { client } = stub(501, { detail: "cassette miss" });
    const error = await rejection(poisonWorld(client, POISON));
    expect(error).toBeInstanceOf(PlaygroundHttpError);
    const http = error as PlaygroundHttpError;
    expect(http.name).toBe("PlaygroundHttpError");
    expect(http.status).toBe(501);
    expect(http.detail).toBe("cassette miss");
    expect(http.message).toBe("POST /playground/poison failed with status 501: cassette miss");
  });

  it("422 array detail [A3]", async () => {
    const { client } = stub(422, {
      detail: [{ type: "missing", loc: ["body", "task"], msg: "Field required" }],
    });
    const error = await rejection(poisonWorld(client, POISON));
    expect(error).toBeInstanceOf(PlaygroundHttpError);
    expect((error as PlaygroundHttpError).status).toBe(422);
    expect((error as PlaygroundHttpError).detail).toBe("invalid request");
  });

  it("a network failure is not wrapped [A3]", async () => {
    const client = createClient<paths>({
      baseUrl: "http://server.test",
      fetch: () => Promise.reject(new TypeError("fetch failed")),
    });
    const error = await rejection(poisonWorld(client, POISON));
    expect(error).toBeInstanceOf(TypeError);
    expect(error).not.toBeInstanceOf(PlaygroundHttpError);
  });

  it("runAttack encodes the id into the path [A3]", async () => {
    const body = {
      attack_id: "A3",
      name: "data_only_poisoning",
      ok: true,
      deferred: false,
      checks: [],
      oracle: ORACLE,
      events: GOLDEN,
    };
    const { client, requests } = stub(200, body);
    const result = await runAttack(client, "A3");
    expect(requests).toEqual([
      { method: "POST", path: "/playground/attacks/A3/run", body: undefined },
    ]);
    expect(result.events).toHaveLength(GOLDEN.length);

    const missing = stub(404, { detail: "unknown attack id" });
    const error = await rejection(runAttack(missing.client, "A99"));
    expect(error).toBeInstanceOf(PlaygroundHttpError);
    expect((error as PlaygroundHttpError).status).toBe(404);
    expect((error as PlaygroundHttpError).detail).toBe("unknown attack id");
  });

  it("runAttack validates the events of the response [I6]", async () => {
    const { client } = stub(200, {
      attack_id: "A3",
      name: "data_only_poisoning",
      ok: true,
      deferred: false,
      checks: [],
      oracle: ORACLE,
      events: [{ type: "nope" }],
    });
    const error = await rejection(runAttack(client, "A3"));
    expect((error as Error).message).toBe("playground response has invalid events");
  });

  it("listAttacks returns the list unchanged [A1-A14]", async () => {
    const cases: AttackCase[] = Array.from({ length: 14 }, (_, index) => ({
      id: `A${index + 1}` as AttackCase["id"],
      category: "instruction_override",
      title: `Attack ${index + 1}`,
      payload: `payload ${index + 1}`,
      expected: { code: "ORIGIN_UNTRUSTED", deciding_check: "origin", verdict: "BLOCK" },
    }));
    const { client, requests } = stub(200, cases);
    const result = await listAttacks(client);
    expect(requests).toEqual([{ method: "GET", path: "/attacks", body: undefined }]);
    expect(result).toEqual(cases);
    expect(result.map((attack) => attack.id)).toEqual(cases.map((attack) => attack.id));
    expect(result.every((attack) => attack.title !== "")).toBe(true);
  });

  it("startHijacked and submitHijackedCall paths [I6]", async () => {
    const session = {
      session_id: "h1",
      run_id: "run-hijacked",
      objectives: [{ objective_id: "o1", title: "Pay the attacker", goal_id: "g1" }],
    };
    const start = stub(200, session);
    const started = await startHijacked(start.client, { scenario: "poisoned_bill", seed: 0 });
    expect(start.requests).toEqual([
      {
        method: "POST",
        path: "/playground/hijacked",
        body: { scenario: "poisoned_bill", seed: 0 },
      },
    ]);
    expect(started).toEqual(session);

    const step = {
      call_id: "h1",
      status: "blocked",
      reason_codes: ["ORIGIN_UNTRUSTED"],
      events: GOLDEN,
      oracle: ORACLE,
      objectives: [{ objective_id: "o1", reached: false }],
    };
    const submit = stub(200, step);
    const result = await submitHijackedCall(submit.client, "h1", HIJACKED_CALL);
    expect(submit.requests).toEqual([
      { method: "POST", path: "/playground/hijacked/h1/calls", body: HIJACKED_CALL },
    ]);
    expect(result.status).toBe("blocked");
    expect(result.events).toHaveLength(GOLDEN.length);

    const duplicate = stub(409, { detail: "duplicate call id" });
    const error = await rejection(submitHijackedCall(duplicate.client, "h1", HIJACKED_CALL));
    expect(error).toBeInstanceOf(PlaygroundHttpError);
    expect((error as PlaygroundHttpError).status).toBe(409);
    expect((error as PlaygroundHttpError).detail).toBe("duplicate call id");
  });

  it("submitHijackedCall validates the events of the step [I6]", async () => {
    const { client } = stub(200, {
      call_id: "h1",
      status: "executed",
      reason_codes: [],
      events: [{ type: "nope" }],
      oracle: ORACLE,
      objectives: [],
    });
    const error = await rejection(submitHijackedCall(client, "h1", HIJACKED_CALL));
    expect((error as Error).message).toBe("playground response has invalid events");
  });

  it("getHijacked path [I6]", async () => {
    const state: HijackedState = {
      session_id: "h1",
      run_id: "run-hijacked",
      calls: 2,
      oracle: ORACLE,
      objectives: [{ objective_id: "o1", reached: true }],
    };
    const { client, requests } = stub(200, state);
    const result = await getHijacked(client, "h1");
    expect(requests).toEqual([{ method: "GET", path: "/playground/hijacked/h1", body: undefined }]);
    expect(result.calls).toBe(2);
    expect(result.objectives).toEqual(state.objectives);
  });

  it("startArena sends the command [A3]", async () => {
    const result = {
      scenario: "poisoned_bill",
      seed: 1,
      lanes: [
        {
          lane: "notary",
          rounds: [
            {
              round: 1,
              vector: "email",
              payload_chars: 40,
              invalid_move: false,
              attacker_goal_reached: false,
              cumulative_successes: 0,
            },
          ],
        },
      ],
    };
    const { client, requests } = stub(200, result);
    expect(await startArena(client, ARENA)).toEqual(result);
    expect(requests).toEqual([{ method: "POST", path: "/playground/arena", body: ARENA }]);

    const tooMany = stub(422, { detail: "too many rounds" });
    const error = await rejection(startArena(tooMany.client, { ...ARENA, rounds: 101 }));
    expect(error).toBeInstanceOf(PlaygroundHttpError);
    expect((error as PlaygroundHttpError).detail).toBe("too many rounds");
  });
});
