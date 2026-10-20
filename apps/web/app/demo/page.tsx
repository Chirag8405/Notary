import { GuidedDemo } from "@/components/guided-demo";

const API_URL = process.env.NEXT_PUBLIC_NOTARY_API_URL ?? "http://localhost:8000";

export const metadata = { title: "Guided demo | NOTARY" };

export default async function DemoPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { step } = await searchParams;
  return (
    <GuidedDemo apiUrl={API_URL} {...(typeof step === "string" ? { initialStep: step } : {})} />
  );
}
