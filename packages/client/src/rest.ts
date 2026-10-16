import createClient from "openapi-fetch";

import type { components, paths } from "./generated/api";

/** Typed REST client; request/response types come from the server's OpenAPI document. */
export function createRestClient(baseUrl: string) {
  return createClient<paths>({ baseUrl });
}

export type RestClient = ReturnType<typeof createRestClient>;

/** The pending endorsements of a run, as the server describes them. */
export type PendingList = components["schemas"]["PendingList"];
/** The audit anchor of a run: the head hash and length the server persisted outside the log. */
export type Anchor = components["schemas"]["Anchor"];

function failed(request: string, status: number): Error {
  return new Error(`${request} failed with status ${status}`);
}

/** The run modes the server offers (`GET /runs/modes`). */
export async function listModes(client: RestClient): Promise<readonly string[]> {
  const { data, response } = await client.GET("/runs/modes");
  if (!response.ok || data === undefined) throw failed("GET /runs/modes", response.status);
  return data.modes;
}

/** The endorsements of a run that still wait for the user (`GET /runs/{run_id}/endorsements`). */
export async function getPendingEndorsements(
  client: RestClient,
  runId: string,
): Promise<PendingList> {
  const { data, response } = await client.GET("/runs/{run_id}/endorsements", {
    params: { path: { run_id: runId } },
  });
  if (!response.ok || data === undefined) {
    throw failed("GET /runs/{run_id}/endorsements", response.status);
  }
  return data;
}

/** The audit anchor of a run, or `null` when the server has none (404). */
export async function getAnchor(client: RestClient, runId: string): Promise<Anchor | null> {
  const { data, response } = await client.GET("/runs/{run_id}/anchor", {
    params: { path: { run_id: runId } },
  });
  if (response.status === 404) return null;
  if (!response.ok || data === undefined)
    throw failed("GET /runs/{run_id}/anchor", response.status);
  return data;
}
