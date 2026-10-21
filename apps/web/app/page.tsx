import { ArrowRight } from "lucide-react";
import Link from "next/link";

import { CountUp } from "@/components/count-up";
import { LiveCheck } from "@/components/live-check";
import { Reveal } from "@/components/reveal";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const STATS = [
  { value: 14, label: "kinds of attack tested" },
  { value: 6, label: "checks on every action" },
  { value: 3, label: "possible answers" },
] as const;

const HOW = [
  {
    title: "Content can lie",
    text: "Agents read emails, files and web pages. An attacker can hide a swapped bank account inside one.",
  },
  {
    title: "The agent acts on it",
    text: "It cannot tell a real bill from a planted one, so it asks to pay the attacker.",
  },
  {
    title: "NOTARY checks first",
    text: "Every action is checked against what you asked for and what you already trust, before it runs.",
  },
] as const;

const OUTCOMES = [
  {
    label: "Allowed",
    text: "It matches what you asked and what you trust. It runs quietly.",
    badge: "border-ok bg-ok-soft text-ok-strong",
    edge: "border-t-ok",
  },
  {
    label: "Needs your approval",
    text: "Something is new. NOTARY pauses and shows you what is different.",
    badge: "border-warn bg-warn-soft text-warn-strong",
    edge: "border-t-warn",
  },
  {
    label: "Stopped",
    text: "It breaks a rule. It never runs.",
    badge: "border-bad bg-bad-soft text-bad-strong",
    edge: "border-t-bad",
  },
] as const;

const LIFT = "transition duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-primary/10";

/** A button that carries a slow light sweep, to pull the eye to the one thing to press. */
function StartButton({ className }: { className?: string }) {
  return (
    <Button
      asChild
      size="lg"
      className={cn("relative h-11 overflow-hidden px-6 text-base", className)}
    >
      <Link href="/demo">
        <span
          aria-hidden="true"
          className="absolute inset-y-0 left-0 w-1/3 animate-shimmer bg-white/25"
        />
        Start the demo <ArrowRight />
      </Link>
    </Button>
  );
}

/** The front page: the idea in one picture, why it matters, how it works, and where to start. */
export default function Home() {
  return (
    <main className="overflow-x-clip">
      <section className="relative isolate px-4 pt-16 pb-20 text-center sm:px-6 sm:pt-24">
        <div aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10">
          <div className="absolute -top-24 left-1/2 size-136 translate-x-[-85%] animate-float rounded-full bg-foreground/10 blur-3xl" />
          <div className="absolute top-10 left-1/2 size-120 translate-x-[5%] animate-float-slow rounded-full bg-foreground/[0.07] blur-3xl" />
          <div className="absolute top-48 left-1/2 size-96 -translate-x-1/2 animate-float rounded-full bg-foreground/5 blur-3xl" />
          <div className="absolute inset-0 bg-[radial-gradient(color-mix(in_oklch,var(--foreground)_14%,transparent)_1px,transparent_1px)] bg-size-[24px_24px] mask-[radial-gradient(ellipse_at_top,black,transparent_70%)]" />
        </div>

        <div className="mx-auto max-w-4xl space-y-6">
          <Badge variant="outline" className="animate-rise bg-background/70 backdrop-blur">
            Stops hidden instructions in emails, files and web pages
          </Badge>
          <h1 className="animate-gradient bg-linear-to-r from-foreground via-muted-foreground to-foreground bg-size-[200%_auto] bg-clip-text pb-2 text-6xl font-bold tracking-tight text-transparent sm:text-8xl">
            NOTARY
          </h1>
          <p className="mx-auto max-w-2xl animate-rise text-2xl font-semibold tracking-tight [animation-delay:160ms] sm:text-4xl">
            Your AI agent just got tricked.{" "}
            <span className="text-muted-foreground">NOTARY says no.</span>
          </p>
          <p className="mx-auto max-w-2xl animate-rise text-lg text-muted-foreground [animation-delay:240ms]">
            AI agents can be tricked by text hidden in emails and files. NOTARY checks every action
            before it runs, so a trick cannot spend your money or leak your data.
          </p>
          <div className="flex animate-rise flex-wrap justify-center gap-3 [animation-delay:320ms]">
            <StartButton />
            <Button
              asChild
              size="lg"
              variant="outline"
              className="h-11 bg-background/70 px-6 text-base backdrop-blur"
            >
              <Link href="/x-ray">Open the Trust X-ray</Link>
            </Button>
          </div>
        </div>

        <div className="mt-14 animate-rise [animation-delay:440ms]">
          <LiveCheck />
        </div>
      </section>

      <div className="mx-auto w-full max-w-5xl space-y-24 px-4 pb-20 sm:px-6">
        <section
          aria-label="In numbers"
          className="grid gap-6 border-y py-10 text-center sm:grid-cols-3"
        >
          {STATS.map((stat, index) => (
            <Reveal key={stat.label} delay={index * 120}>
              <p className="bg-linear-to-r from-foreground to-muted-foreground bg-clip-text text-5xl font-bold tracking-tight text-transparent">
                <CountUp to={stat.value} />
              </p>
              <p className="mt-1 text-sm text-muted-foreground">{stat.label}</p>
            </Reveal>
          ))}
        </section>

        <section aria-labelledby="how" className="space-y-8">
          <Reveal>
            <h2 id="how" className="text-3xl font-semibold tracking-tight">
              How it works
            </h2>
          </Reveal>
          <div className="grid gap-4 md:grid-cols-3">
            {HOW.map((part, index) => (
              <Reveal key={part.title} delay={index * 140}>
                <div className={cn("h-full rounded-xl border bg-card p-6", LIFT)}>
                  <p className="bg-linear-to-br from-foreground to-muted-foreground bg-clip-text text-5xl font-bold text-transparent">
                    {index + 1}
                  </p>
                  <h3 className="mt-3 text-lg font-semibold">{part.title}</h3>
                  <p className="mt-2 text-sm text-muted-foreground">{part.text}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </section>

        <section aria-labelledby="outcomes" className="space-y-8">
          <Reveal>
            <h2 id="outcomes" className="text-3xl font-semibold tracking-tight">
              Three possible answers
            </h2>
          </Reveal>
          <div className="grid gap-4 md:grid-cols-3">
            {OUTCOMES.map((outcome, index) => (
              <Reveal key={outcome.label} delay={index * 140}>
                <div
                  className={cn(
                    "h-full space-y-3 rounded-xl border border-t-4 bg-card p-6",
                    outcome.edge,
                    LIFT,
                  )}
                >
                  <Badge variant="outline" className={outcome.badge}>
                    {outcome.label}
                  </Badge>
                  <p className="text-sm text-muted-foreground">{outcome.text}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </section>

        <Reveal>
          <section className="animate-gradient rounded-2xl border bg-linear-to-r from-foreground/5 via-foreground/10 to-foreground/5 bg-size-[200%_auto] p-10 text-center sm:p-14">
            <h2 className="text-3xl font-semibold tracking-tight">See it in three minutes</h2>
            <p className="mx-auto mt-3 max-w-xl text-muted-foreground">
              Watch an agent get tricked, watch NOTARY stop it, then try to break it yourself.
            </p>
            <StartButton className="mt-6" />
          </section>
        </Reveal>
      </div>
    </main>
  );
}
