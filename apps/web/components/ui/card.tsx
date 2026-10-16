import type * as React from "react";

import { cn } from "@/lib/utils";

export function Card({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div className={cn("rounded-xl border bg-background p-4 shadow-sm", className)} {...props} />
  );
}

export function CardTitle({ className, ...props }: React.ComponentProps<"h2">) {
  return <h2 className={cn("mb-2 text-sm font-semibold", className)} {...props} />;
}
