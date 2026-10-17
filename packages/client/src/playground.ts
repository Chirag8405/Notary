import { EventSchema, type Event } from "@notary/schema";

import type { components } from "./generated/api";
import type { RestClient } from "./rest";

type Schemas = components["schemas"];

export type PoisonWorldBody = Schemas["PoisonWorldCommand"];
export type ArenaStartBody = Schemas["ArenaStartCommand"];
export type HijackedToolCallBody = Schemas["HijackedToolCallCommand"];
export type HijackedStartBody = Schemas["HijackedStart"];
export type HijackedSession = Schemas["HijackedSession"];
export type HijackedObjective = Schemas["Objective"];
export type ObjectiveStatus = Schemas["ObjectiveStatus"];
export type HijackedState = Schemas["HijackedState"];
export type ArenaResult = Schemas["ArenaResult"];
export type ArenaLane = Schemas["ArenaLane"];
export type ArenaRound = Schemas["ArenaRound"];
export type AttackCase = Schemas["AttackCase"];
export type CheckSummary = Schemas["CheckSummary"];

/** `Omit<T, "events"> & { events: readonly Event[] }` for the responses that carry events. */
export type WithEvents<T extends { events: unknown }> = Omit<T, "events"> & {
  events: readonly Event[];
};
export type LaneRun = WithEvents<Schemas["LaneRun"]>;
export type PoisonResponse = Omit<Schemas["PoisonResponse"], "runs"> & {
  runs: readonly LaneRun[];
};
export type AttackRunResponse = WithEvents<Schemas["AttackRunResponse"]>;
export type HijackedStep = WithEvents<Schemas["HijackedStep"]>;

/** A non-2xx answer of a playground route: the HTTP status and the server's `detail` text. */
export class PlaygroundHttpError extends Error {
  override readonly name = "PlaygroundHttpError";
  readonly status: number;
  /** The server's `detail` string; "invalid request" when `detail` is not a string. */
  readonly detail: string;

  constructor(request: string, status: number, detail: string) {
    super(`${request} failed with status ${status}: ${detail}`);
    this.status = status;
    this.detail = detail;
  }
}

function fail(request: string, response: Response, error: unknown): PlaygroundHttpError {
  const detail =
    typeof error === "object" && error !== null && "detail" in error ? error.detail : undefined;
  return new PlaygroundHttpError(
    request,
    response.status,
    typeof detail === "string" ? detail : "invalid request",
  );
}

function events(raw: unknown): readonly Event[] {
  const result = EventSchema.array().safeParse(raw);
  if (!result.success) throw new Error("playground response has invalid events");
  return result.data;
}

/** Poison-the-world: run the chosen lanes on a scenario with the judge's payload (`POST /playground/poison`). */
export async function poisonWorld(
  client: RestClient,
  command: PoisonWorldBody,
): Promise<PoisonResponse> {
  const request = "POST /playground/poison";
  const { data, response, error } = await client.POST("/playground/poison", { body: command });
  if (!response.ok || data === undefined) throw fail(request, response, error);
  return {
    ...data,
    runs: data.runs.map((run) => ({ ...run, events: events(run.events) })),
  };
}

/** The attack library A1-A14 (`GET /attacks`). */
export async function listAttacks(client: RestClient): Promise<readonly AttackCase[]> {
  const { data, response, error } = await client.GET("/attacks");
  if (!response.ok || data === undefined) throw fail("GET /attacks", response, error);
  return data;
}

/** Run one library attack (`POST /playground/attacks/{attack_id}/run`); the id is sent as given. */
export async function runAttack(client: RestClient, attackId: string): Promise<AttackRunResponse> {
  const { data, response, error } = await client.POST("/playground/attacks/{attack_id}/run", {
    params: { path: { attack_id: attackId } },
  });
  if (!response.ok || data === undefined) {
    throw fail("POST /playground/attacks/{attack_id}/run", response, error);
  }
  return { ...data, events: events(data.events) };
}

/** Start a Hijacked Mode session (`POST /playground/hijacked`). */
export async function startHijacked(
  client: RestClient,
  body: HijackedStartBody,
): Promise<HijackedSession> {
  const { data, response, error } = await client.POST("/playground/hijacked", { body });
  if (!response.ok || data === undefined) throw fail("POST /playground/hijacked", response, error);
  return data;
}

/** Submit a raw tool call to a Hijacked Mode session (`POST /playground/hijacked/{session_id}/calls`). */
export async function submitHijackedCall(
  client: RestClient,
  sessionId: string,
  command: HijackedToolCallBody,
): Promise<HijackedStep> {
  const { data, response, error } = await client.POST("/playground/hijacked/{session_id}/calls", {
    params: { path: { session_id: sessionId } },
    body: command,
  });
  if (!response.ok || data === undefined) {
    throw fail("POST /playground/hijacked/{session_id}/calls", response, error);
  }
  return { ...data, events: events(data.events) };
}

/** The state of a Hijacked Mode session (`GET /playground/hijacked/{session_id}`). */
export async function getHijacked(client: RestClient, sessionId: string): Promise<HijackedState> {
  const { data, response, error } = await client.GET("/playground/hijacked/{session_id}", {
    params: { path: { session_id: sessionId } },
  });
  if (!response.ok || data === undefined) {
    throw fail("GET /playground/hijacked/{session_id}", response, error);
  }
  return data;
}

/** Start the attacker arena (`POST /playground/arena`). */
export async function startArena(
  client: RestClient,
  command: ArenaStartBody,
): Promise<ArenaResult> {
  const { data, response, error } = await client.POST("/playground/arena", { body: command });
  if (!response.ok || data === undefined) throw fail("POST /playground/arena", response, error);
  return data;
}
