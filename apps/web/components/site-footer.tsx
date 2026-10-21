import Link from "next/link";

/** The foot of every page: where to go next and what the project is. */
export function SiteFooter() {
  return (
    <footer className="border-t">
      <div className="mx-auto flex w-full max-w-[1600px] flex-col gap-2 px-4 py-6 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <p>NOTARY: a deterministic check between an AI agent and the actions it takes.</p>
        <nav aria-label="Footer" className="flex gap-4">
          <Link href="/demo" className="hover:text-foreground">
            Guided demo
          </Link>
          <Link href="/x-ray" className="hover:text-foreground">
            Trust X-ray
          </Link>
          <Link href="/playground" className="hover:text-foreground">
            Playground
          </Link>
        </nav>
      </div>
    </footer>
  );
}
