"use client";

import { useState } from "react";

import { Button } from "@/components/ui/button";
import { HIJACKED_TOOLS, findTool } from "@/lib/hijacked-tools";
import type { ToolEffect } from "@/lib/hijacked-tools";
import { QUICK_ATTEMPTS } from "@/lib/hijacked-state";

export interface CallFormProps {
  /** True until a session exists and while a call is in flight. */
  disabled: boolean;
  onSubmit: (tool: string, values: Record<string, string>) => void;
}

const EFFECTS: readonly ToolEffect[] = ["read", "write", "irreversible"];
const FIELD = "h-9 rounded-md border border-input bg-background px-3 text-sm";

/** The tool select, one input per parameter of the chosen tool, quick attempts and Submit. */
export function CallForm({ disabled, onSubmit }: CallFormProps) {
  const [tool, setTool] = useState(
    () => HIJACKED_TOOLS.find((item) => item.effect === "read")?.name ?? "",
  );
  const [values, setValues] = useState<Readonly<Record<string, string>>>({});
  const spec = findTool(tool);

  return (
    <form
      className="space-y-3"
      aria-label="Tool call"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(tool, { ...values });
      }}
    >
      <div className="flex flex-wrap gap-2" aria-label="Quick attempts" role="group">
        {QUICK_ATTEMPTS.map((attempt) => (
          <Button
            key={attempt.id}
            type="button"
            variant="outline"
            className="h-8 text-xs"
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
      <div className="flex flex-col gap-1">
        <label htmlFor="hijacked-tool">Tool</label>
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
                  {item.name}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
        {spec === undefined ? null : (
          <p className="text-xs text-muted-foreground">{spec.description}</p>
        )}
      </div>
      {spec?.params.map((param) => (
        <div key={`${spec.name}.${param.name}`} className="flex flex-col gap-1">
          <span className="flex gap-1">
            <label htmlFor={`hijacked-param-${param.name}`}>{param.name}</label>
            {param.required ? <span aria-hidden="true">*</span> : null}
          </span>
          <input
            id={`hijacked-param-${param.name}`}
            data-param={param.name}
            type="text"
            className={FIELD}
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
      <Button type="submit" className="h-9 text-sm" disabled={disabled}>
        Submit call
      </Button>
    </form>
  );
}
