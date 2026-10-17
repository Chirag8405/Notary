import { PlaygroundView } from "@/components/playground-view";
import { parsePlaygroundParams } from "@/lib/playground-state";

const API_URL = process.env.NEXT_PUBLIC_NOTARY_API_URL ?? "http://localhost:8000";

export default async function PlaygroundPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = parsePlaygroundParams(await searchParams);
  return <PlaygroundView apiUrl={API_URL} initialMode={params.mode} />;
}
