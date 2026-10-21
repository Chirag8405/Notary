"use client";

import { useState } from "react";

import { Disclosure } from "@/components/disclosure";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { HIJACKED_TOOLS, findTool } from "@/lib/hijacked-tools";
import type { ToolEffect } from "@/lib/hijacked-tools";
import { QUICK_ATTEMPTS } from "@/lib/hijacked-state";
import { paramText, toolText } from "@/lib/plain-language";

export interface CallFormProps {
  /** True until a session exists and while a call is in flight. */
  disabled: boolean;
  onSubmit: (tool: string, values: Record<string, string>) => void;
}

const EFFECTS: readonly ToolEffect[] = ["read", "write", "irreversible"];
const FIELD = "h-9 w-full rounded-md border border-input bg-background px-3 text-sm shadow-xs";

/** The tool select, one input per parameter of the chosen tool, quick attempts and Submit. */
export function CallForm({ disabled, onSubmit }: CallFormProps) {
  const [tool, setTool] = useState(
    () => HIJACKED_TOOLS.find((item) => item.effect === "read")?.name ?? "",
  );
  const [values, setValues] = useState<Readonly<Record<string, string>>>({});
  const spec = findTool(tool);
  const filled = Object.entries(values).filter(([, value]) => value !== "");
  const preview = `Will send: ${toolText(tool)}${
    filled.length === 0 ? "" : ` (${filled.map(([name, value]) => `${name}=${value}`).join(", ")})`
  }`;

  return (
    <form
      className="space-y-3"
      aria-label="Tool call"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(tool, { ...values });
      }}
    >
      <p className="text-sm font-medium">Quick attempts</p>
      <div className="flex flex-wrap gap-2" aria-label="Quick attempts" role="group">
        {QUICK_ATTEMPTS.map((attempt) => (
          <Button
            key={attempt.id}
            type="button"
            variant="outline"
            className="h-9 text-sm"
            disabled={disabled}
            data-quick-attempt={attempt.id}
            onClick={() => {
              setTool(attempt.tool);
              setValues({ ...attempt.values });
            }}
          >
            {attempt.title}
          </Button>
        ))}
      </div>
      <Disclosure title="Or build your own call" hint="any of the tools, any values">
        <div className="flex max-w-xl flex-col gap-2">
          <Label htmlFor="hijacked-tool">Tool</Label>
          <select
            id="hijacked-tool"
            className={FIELD}
            value={tool}
            disabled={disabled}
            onChange={(event) => {
              setTool(event.target.value);
              setValues({});
            }}
          >
            {EFFECTS.map((effect) => (
              <optgroup key={effect} label={effect}>
                {HIJACKED_TOOLS.filter((item) => item.effect === effect).map((item) => (
                  <option key={item.name} value={item.name}>
                    {toolText(item.name)} ({item.name})
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
          {spec === undefined ? null : (
            <p className="text-xs text-muted-foreground">{spec.description}</p>
          )}
        </div>
        <div className="grid max-w-xl gap-4 sm:grid-cols-2">
          {spec?.params.map((param) => (
            <div key={`${spec.name}.${param.name}`} className="flex flex-col gap-2">
              <span className="flex gap-1">
                <Label htmlFor={`hijacked-param-${param.name}`}>{param.name}</Label>
                <span className="text-xs text-muted-foreground">({paramText(param.name)})</span>
                {param.required ? <span aria-hidden="true">*</span> : null}
              </span>
              <Input
                id={`hijacked-param-${param.name}`}
                data-param={param.name}
                type="text"
                aria-required={param.required}
                disabled={disabled}
                value={values[param.name] ?? ""}
                onChange={(event) => {
                  const next = event.target.value;
                  setValues((current) => ({ ...current, [param.name]: next }));
                }}
              />
            </div>
          ))}
        </div>
      </Disclosure>
      <p className="text-sm text-muted-foreground" data-testid="call-preview">
        {preview}
      </p>
      <Button type="submit" size="lg" disabled={disabled}>
        Submit call
      </Button>
    </form>
  );
}
