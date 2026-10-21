import { Bot, Mail, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";

const PARTS = [
  {
    icon: Mail,
    title: "Content can lie",
    text: "An AI agent reads emails, files and web pages. An attacker can hide an order, or a swapped number, inside them.",
  },
  {
    icon: Bot,
    title: "The agent proposes actions",
    text: "Based on what it read, the agent asks to pay, send or delete. It cannot tell a real bill from a planted one.",
  },
  {
    icon: ShieldCheck,
    title: "NOTARY checks each action",
    text: "Before anything runs, NOTARY asks: did you ask for this, do you know these details, and is it within your limits?",
  },
] as const;

const OUTCOMES = [
  ["Allowed", "It matches what you asked and what you already trust. It runs quietly."],
  ["Needs your approval", "Something is new to you. NOTARY pauses and shows you the difference."],
  ["Stopped", "It breaks a rule you set. It never runs."],
] as const;

/** A side panel that explains the idea in three steps and the three outcomes. */
export function HowItWorks({ children }: { children: ReactNode }) {
  return (
    <Sheet>
      <SheetTrigger asChild>{children}</SheetTrigger>
      <SheetContent className="overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle>How NOTARY works</SheetTitle>
          <SheetDescription>
            A short guard that sits between an AI agent and the actions it takes.
          </SheetDescription>
        </SheetHeader>
        <div className="space-y-6 px-4 pb-6">
          <ol className="space-y-4">
            {PARTS.map((part) => (
              <li key={part.title} className="flex gap-3">
                <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted">
                  <part.icon className="size-4" />
                </span>
                <div>
                  <p className="font-medium">{part.title}</p>
                  <p className="text-sm text-muted-foreground">{part.text}</p>
                </div>
              </li>
            ))}
          </ol>
          <div className="space-y-2">
            <p className="text-sm font-medium">The three outcomes</p>
            <dl className="space-y-2 text-sm">
              {OUTCOMES.map(([name, text]) => (
                <div key={name} className="rounded-lg border p-3">
                  <dt className="font-medium">{name}</dt>
                  <dd className="text-muted-foreground">{text}</dd>
                </div>
              ))}
            </dl>
          </div>
          <p className="text-xs text-muted-foreground">
            Honest limit: NOTARY cannot stop a choice you approve yourself, so read the approval
            screen before you say yes.
          </p>
        </div>
      </SheetContent>
    </Sheet>
  );
}
