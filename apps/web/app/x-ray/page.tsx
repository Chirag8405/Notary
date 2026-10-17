import { XRayView } from "@/components/x-ray-view";
import { parseXRayParams } from "@/lib/x-ray-state";

const API_URL = process.env.NEXT_PUBLIC_NOTARY_API_URL ?? "http://localhost:8000";

export default async function XRayPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = parseXRayParams(await searchParams);
  return (
    <XRayView
      apiUrl={API_URL}
      scenario={params.scenario}
      mode={params.mode}
      initialViewMode={params.viewMode}
      {...(params.step === undefined ? {} : { initialStep: params.step })}
    />
  );
}
