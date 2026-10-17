import { cn } from "cn";
import * as React from "react";

function Separator({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="separator"
      role="none"
      className={cn("h-px w-full shrink-0 bg-border", className)}
      {...props}
    />
  );
}

export { Separator };
