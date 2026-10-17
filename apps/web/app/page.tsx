import { redirect } from "next/navigation";

import { rootRedirectUrl } from "@/lib/demo-steps";

/** There is no landing page: the root opens the first step of the demo (the three-lane view). */
export default function Home(): never {
  redirect(rootRedirectUrl());
}
