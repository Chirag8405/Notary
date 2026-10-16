import createClient from "openapi-fetch";

import type { paths } from "./generated/api";

/** Typed REST client; request/response types come from the server's OpenAPI document. */
export function createRestClient(baseUrl: string) {
  return createClient<paths>({ baseUrl });
}

export type RestClient = ReturnType<typeof createRestClient>;
