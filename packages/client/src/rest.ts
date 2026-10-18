import createClient from "openapi-fetch";

import type { components, paths } from "./generated/api";

/** Typed REST client; request/response types come from the server's OpenAPI document. */
export function createRestClient(baseUrl: string) {
  return createClient<paths>({ baseUrl });
}

export type RestClient = ReturnType<typeof createRestClient>;

/** One run of the MCP proxy, as listed by `GET /mcp/runs`. */
export type McpRunInfo = components["schemas"]["McpRunInfo"];

/**
 * The MCP proxy runs the server can show, newest first (`GET /mcp/runs`). The server answers 404
 * when it was started without `NOTARY_MCP_RUNS_DIR`; that is an error here, like any other failure.
 */
export async function listMcpRuns(client: RestClient): Promise<readonly McpRunInfo[]> {
  const { data, response } = await client.GET("/mcp/runs");
  if (!response.ok || data === undefined) throw failed("GET /mcp/runs", response.status);
  return data.runs;
}

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
