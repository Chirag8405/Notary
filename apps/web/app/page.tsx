import Link from "next/link";

import { Button } from "@/components/ui/button";

export default function Home() {
  return (
    <main className="mx-auto max-w-3xl space-y-4 p-8">
      <h1 className="text-2xl font-bold">NOTARY</h1>
      <p>A deterministic security layer against indirect prompt injection in AI agents.</p>
      <Button asChild>
        <Link href="/x-ray">Open Trust X-ray</Link>
      </Button>
    </main>
  );
}
