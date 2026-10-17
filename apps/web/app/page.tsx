import { redirect } from "next/navigation";

import { xrayUrl } from "@/lib/x-ray-state";

/** There is no landing page: the root opens the first step of the demo (the three-lane view). */
export default function Home(): never {
  redirect(xrayUrl({ scenario: "poisoned_bill", mode: "cassette", viewMode: "three-lane" }));
}
