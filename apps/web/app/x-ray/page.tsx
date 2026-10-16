import { XRayView } from "@/components/x-ray-view";

const API_URL = process.env.NEXT_PUBLIC_NOTARY_API_URL ?? "http://localhost:8000";

export default function XRayPage() {
  return <XRayView apiUrl={API_URL} scenario="poisoned_bill" />;
}
