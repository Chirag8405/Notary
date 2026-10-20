"use client";

import { useRunStream } from "@notary/client/react";
import type { WebSocketFactory } from "@notary/client";
import { cardOutcomes, foldEvents } from "@notary/ui";
import type { LaneName } from "@notary/ui";
import {
  ArrowLeft,
  ArrowRight,
  CircleHelp,
  ExternalLink,
  RotateCcw,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import { ApprovalDialog } from "@/components/approval-dialog";
import { EffectsList } from "@/components/effects-list";
import { HowItWorks } from "@/components/how-it-works";
import { OutcomeBanner } from "@/components/outcome-banner";
import { RunTimeline } from "@/components/run-timeline";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { TooltipProvider } from "@/components/ui/tooltip";
import { GUIDED_STEPS, stepIndex, summarizeOutcome } from "@/lib/guided";
import type { GuidedStep } from "@/lib/guided";
import { xrayUrl, streamProblem } from "@/lib/x-ray-state";

export interface GuidedDemoProps {
  apiUrl: string;
  /** The step named in the address (`attack`, `pause`, `normal`, `try`). */
  initialStep?: string;
  /** Test seam: the socket factory. */
  webSocket?: WebSocketFactory;
}

const LANE_TEXT: Record<LaneName, { title: string; blurb: string }> = {
  undefended: {
    title: "Without protection",
    blurb: "The agent does whatever the content it reads tells it to.",
  },
  classifier: {
    title: "A basic filter",
    blurb: "A keyword filter looks for suspicious instructions. A swapped number has none.",
  },
  notary: { title: "With NOTARY", blurb: "Every action is checked before it runs." },
};

function StreamProblem({
  apiUrl,
  stream,
}: {
  apiUrl: string;
  stream: ReturnType<typeof useRunStream>;
}) {
  if (stream.status !== "error") return null;
  const problem = streamProblem({
    closeCode: stream.closeCode,
    message: stream.error.message,
    apiUrl,
    mode: "cassette",
  });
  return <Alert variant="destructive">{problem.text}</Alert>;
}

/** One agent with no approval step: what it did and how it ended. */
function LaneCard({
  apiUrl,
  scenario,
  lane,
  webSocket,
}: {
  apiUrl: string;
  scenario: string;
  lane: Extract<LaneName, "undefended" | "classifier">;
  webSocket: WebSocketFactory | undefined;
}) {
  const stream = useRunStream(apiUrl, scenario, {
    lane,
    mode: "cassette",
    ...(webSocket === undefined ? {} : { webSocket }),
  });
  const view = useMemo(() => foldEvents(stream.events), [stream.events]);
  const outcome = summarizeOutcome(view, { unresolved: 0, rejected: 0 });
  const text = LANE_TEXT[lane];
  return (
    <Card data-lane={lane}>
      <CardHeader>
        <CardTitle>{text.title}</CardTitle>
        <CardDescription>{text.blurb}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <StreamProblem apiUrl={apiUrl} stream={stream} />
        <RunTimeline view={view} />
        <OutcomeBanner outcome={outcome} compact />
      </CardContent>
    </Card>
  );
}

function AttackStep({
  apiUrl,
  scenario,
  webSocket,
  onNext,
}: {
  apiUrl: string;
  scenario: string;
  webSocket: WebSocketFactory | undefined;
  onNext: () => void;
}) {
  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <LaneCard apiUrl={apiUrl} scenario={scenario} lane="undefended" webSocket={webSocket} />
      <LaneCard apiUrl={apiUrl} scenario={scenario} lane="classifier" webSocket={webSocket} />
      <Card className="border-dashed">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="size-4" /> {LANE_TEXT.notary.title}
          </CardTitle>
          <CardDescription>{LANE_TEXT.notary.blurb}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Both agents above paid the attacker. See what changes when NOTARY sits in between.
          </p>
          <Button type="button" onClick={onNext}>
            See NOTARY stop it <ArrowRight />
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

/** The NOTARY lane of one scenario, with the approval dialog when it pauses. */
function NotaryRun({
  apiUrl,
  scenario,
  webSocket,
}: {
  apiUrl: string;
  scenario: string;
  webSocket: WebSocketFactory | undefined;
}) {
  const [attempt, setAttempt] = useState(0);
  return (
    <NotaryAttempt
      key={attempt}
      apiUrl={apiUrl}
      scenario={scenario}
      webSocket={webSocket}
      onRunAgain={() => {
        setAttempt((value) => value + 1);
      }}
    />
  );
}

function NotaryAttempt({
  apiUrl,
  scenario,
  webSocket,
  onRunAgain,
}: {
  apiUrl: string;
  scenario: string;
  webSocket: WebSocketFactory | undefined;
  onRunAgain: () => void;
}) {
  const stream = useRunStream(apiUrl, scenario, {
    lane: "notary",
    mode: "cassette",
    ...(webSocket === undefined ? {} : { webSocket }),
  });
  const view = useMemo(() => foldEvents(stream.events), [stream.events]);
  const outcomes = useMemo(() => cardOutcomes(stream.events), [stream.events]);
  const toolByCallId = useMemo(
    () => Object.fromEntries(view.calls.map((call) => [call.callId, call.tool])),
    [view.calls],
  );
  const kinds = view.endorsements.map(
    (item) => outcomes.byEndorsementId.get(item.endorsement.endorsement_id)?.kind ?? "open",
  );
  const outcome = summarizeOutcome(view, {
    unresolved: kinds.filter((kind) => kind === "open").length,
    rejected: kinds.filter((kind) => kind === "rejected").length,
  });

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <Card>
        <CardHeader>
          <CardTitle>What the agent did</CardTitle>
          <CardDescription>Each action, and what NOTARY decided about it.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <StreamProblem apiUrl={apiUrl} stream={stream} />
          <RunTimeline view={view} />
        </CardContent>
      </Card>
      <div className="space-y-4">
        <OutcomeBanner outcome={outcome} />
        <Card>
          <CardHeader>
            <CardTitle>What changed</CardTitle>
          </CardHeader>
          <CardContent>
            <EffectsList view={view} />
          </CardContent>
        </Card>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" onClick={onRunAgain}>
            <RotateCcw /> Run again
          </Button>
          <Button asChild variant="ghost">
            <Link href={xrayUrl({ scenario, mode: "cassette", viewMode: "single" })}>
              Open in Trust X-ray <ExternalLink />
            </Link>
          </Button>
        </div>
      </div>
      {view.runId === null || view.endorsements.length === 0 ? null : (
        <ApprovalDialog
          runId={view.runId}
          endorsements={view.endorsements}
          events={stream.events}
          send={stream.send}
          toolByCallId={toolByCallId}
          connected={stream.status === "open" || stream.status === "connecting"}
          onRunAgain={onRunAgain}
        />
      )}
    </div>
  );
}

function TryStep() {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Be the hijacked agent</CardTitle>
          <CardDescription>
            Pretend the attacker has taken over the agent. Order it to pay, email or delete, and see
            whether NOTARY lets it happen.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild>
            <Link href="/playground?mode=hijacked">
              Start playing <ArrowRight />
            </Link>
          </Button>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Explore more</CardTitle>
          <CardDescription>
            Run every known attack with one click, or watch an attacker try again and again.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button asChild variant="outline">
            <Link href="/playground?mode=library">Attack library</Link>
          </Button>
          <Button asChild variant="outline">
            <Link href="/playground?mode=arena">Attacker arena</Link>
          </Button>
          <Button asChild variant="ghost">
            <Link href="/x-ray">Trust X-ray (advanced)</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

function StepBody({
  step,
  apiUrl,
  webSocket,
  onNext,
}: {
  step: GuidedStep;
  apiUrl: string;
  webSocket: WebSocketFactory | undefined;
  onNext: () => void;
}) {
  if (step.id === "attack" && step.scenario !== null) {
    return (
      <AttackStep apiUrl={apiUrl} scenario={step.scenario} webSocket={webSocket} onNext={onNext} />
    );
  }
  if (step.scenario !== null) {
    return <NotaryRun apiUrl={apiUrl} scenario={step.scenario} webSocket={webSocket} />;
  }
  return <TryStep />;
}

/** The guided path: four steps, one idea each, with Back and Next. */
export function GuidedDemo({ apiUrl, initialStep, webSocket }: GuidedDemoProps) {
  const [index, setIndex] = useState(() => stepIndex(initialStep));
  const step = GUIDED_STEPS[index] ?? GUIDED_STEPS[0];
  if (step === undefined) return null;

  const go = (next: number) => {
    const target = GUIDED_STEPS[next];
    if (target === undefined) return;
    setIndex(next);
    window.history.replaceState(null, "", `/demo?step=${target.id}`);
  };

  return (
    <TooltipProvider>
      <main className="mx-auto w-full max-w-6xl space-y-6 px-4 py-8 sm:px-6">
        <header className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-2">
            <Badge variant="secondary">
              Step {index + 1} of {GUIDED_STEPS.length}
            </Badge>
            <h1 className="text-3xl font-semibold tracking-tight">{step.title}</h1>
            <p className="max-w-2xl text-muted-foreground">{step.summary}</p>
            {step.asked === null ? null : (
              <p className="text-sm">
                <span className="text-muted-foreground">You asked the agent:</span>{" "}
                <span className="rounded-md bg-muted px-2 py-1 font-medium">
                  &ldquo;{step.asked}&rdquo;
                </span>
              </p>
            )}
          </div>
          <HowItWorks>
            <Button type="button" variant="outline">
              <CircleHelp /> How this works
            </Button>
          </HowItWorks>
        </header>

        <div className="space-y-3">
          <Progress value={((index + 1) / GUIDED_STEPS.length) * 100} aria-label="Progress" />
          <Tabs
            value={step.id}
            onValueChange={(id) => {
              go(stepIndex(id));
            }}
          >
            <TabsList variant="line" aria-label="Demo steps" className="w-full justify-start">
              {GUIDED_STEPS.map((item, position) => (
                <TabsTrigger key={item.id} value={item.id}>
                  {position + 1}. {item.title}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </div>

        <StepBody
          key={step.id}
          step={step}
          apiUrl={apiUrl}
          webSocket={webSocket}
          onNext={() => {
            go(index + 1);
          }}
        />

        <nav aria-label="Step navigation" className="flex items-center justify-between">
          <Button
            type="button"
            variant="outline"
            disabled={index === 0}
            onClick={() => {
              go(index - 1);
            }}
          >
            <ArrowLeft /> Back
          </Button>
          <Button
            type="button"
            disabled={index === GUIDED_STEPS.length - 1}
            onClick={() => {
              go(index + 1);
            }}
          >
            Next <ArrowRight />
          </Button>
        </nav>
      </main>
    </TooltipProvider>
  );
}
