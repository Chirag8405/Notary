import { XRayView } from "@/components/x-ray-view";
import { parseXRayParams } from "@/lib/x-ray-state";

const API_URL = process.env.NEXT_PUBLIC_NOTARY_API_URL ?? "http://localhost:8000";

export default async function XRayPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const raw = await searchParams;
  const params = parseXRayParams(raw);
  // The fixed replay (golden) cannot answer an approval, so an address that names no mode opens the
  // recorded run, which can. A mode named in the address is always honoured.
  const mode = [raw.mode].flat()[0] === undefined ? "cassette" : params.mode;
  return (
    <XRayView
      apiUrl={API_URL}
      scenario={params.scenario}
      mode={mode}
      initialViewMode={params.viewMode}
      {...(params.step === undefined ? {} : { initialStep: params.step })}
    />
  );
}
