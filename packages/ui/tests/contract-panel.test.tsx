import type { IntentContract } from "@notary/schema";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import * as ui from "../src";
import { ContractPanel } from "../src/ContractPanel";
import { STREAMS, load, must } from "./golden";
import type { StreamName } from "./golden";

afterEach(cleanup);

function contractOf(name: StreamName): IntentContract {
  const started = load(name).find((event) => event.type === "run_started");
  if (started?.type !== "run_started") throw new Error("fixture missing run_started");
  return started.contract;
}

function deepFreeze<T>(input: T): T {
  if (input !== null && typeof input === "object" && !Object.isFrozen(input)) {
    Object.freeze(input);
    for (const key of Object.keys(input)) deepFreeze((input as Record<string, unknown>)[key]);
  }
  return input;
}

function tool(name: string): HTMLElement {
  return must(document.querySelector<HTMLElement>(`[data-tool="${name}"]`), `tool ${name}`);
}

function param(toolName: string, name: string): HTMLElement {
  return must(tool(toolName).querySelector<HTMLElement>(`[data-param="${name}"]`), name);
}

describe("ContractPanel on the golden contracts", () => {
  it("renders the NOTARY poisoned contract as frozen [A3]", () => {
    const contract = contractOf("poisoned_bill.notary");
    render(<ContractPanel contract={contract} />);
    expect(screen.getByTestId("intent").textContent).toBe(contract.user_intent);

    // The streams hold the contract as the user approved it: payee endorse, amount free.
    expect(contract.allowed_tools.find((t) => t.tool === "pay_bill")?.params.payee?.kind).toBe(
      "endorse",
    );
    const payee = param("pay_bill", "payee");
    expect(payee.textContent).toBe("payee: endorse");
    expect(payee.getAttribute("data-tone")).toBe("gated");
    expect(payee.getAttribute("data-marker-kind")).toBe("endorse");
    const amount = param("pay_bill", "amount");
    expect(amount.textContent).toBe("amount: free");
    expect(amount.getAttribute("data-tone")).toBe("open");
    expect(amount.getAttribute("data-marker-kind")).toBe("free");
  });

  it("renders the legitimate contract with the stream's tools and budget [I2]", () => {
    const contract = contractOf("legitimate_bill.notary");
    render(<ContractPanel contract={contract} />);
    const tools = [...screen.getByLabelText("Allowed tools").children].map((li) =>
      li.getAttribute("data-tool"),
    );
    expect(tools).toEqual(contract.allowed_tools.map((t) => t.tool));

    const budget = screen.getByLabelText("Effect budget");
    const pairs = [...budget.querySelectorAll("dt")].map((dt) => [
      dt.textContent,
      dt.nextElementSibling?.textContent,
    ]);
    expect(pairs).toEqual(Object.entries(contract.budget).map(([k, v]) => [k, String(v)]));
    expect(pairs).toHaveLength(5);
  });

  it("renders every golden contract with the label, in contract order [I6]", () => {
    for (const name of STREAMS) {
      const contract = contractOf(name);
      const { unmount } = render(<ContractPanel contract={contract} />);
      expect(screen.getByLabelText("Intent contract")).toBeTruthy();
      expect(
        [...screen.getByLabelText("Allowed tools").children].map((li) =>
          li.getAttribute("data-tool"),
        ),
      ).toEqual(contract.allowed_tools.map((t) => t.tool));
      unmount();
    }
  });

  it("tags irreversible tools and no others [I1]", () => {
    const contract = contractOf("poisoned_bill.notary");
    expect(contract.authorized_irreversible).toEqual(["pay_bill"]);
    render(<ContractPanel contract={contract} />);
    expect(tool("pay_bill").getAttribute("data-irreversible")).toBe("true");
    expect(tool("pay_bill").querySelector("[data-irreversible-tag]")?.textContent).toBe(
      "irreversible",
    );
    expect(tool("read_inbox").hasAttribute("data-irreversible")).toBe(false);
    expect(tool("read_inbox").querySelector("[data-irreversible-tag]")).toBeNull();
    const list = screen.getByLabelText("Authorized irreversible");
    expect([...list.querySelectorAll("li")].map((li) => li.textContent)).toEqual(["pay_bill"]);
  });

  it('shows "no parameters" for a tool without parameters [I6]', () => {
    render(<ContractPanel contract={contractOf("poisoned_bill.notary")} />);
    expect(within(tool("read_inbox")).getByText("no parameters")).toBeTruthy();
    expect(tool("read_inbox").querySelector("[data-param]")).toBeNull();
  });

  it("gives every chip a tone, a kind and visible tone text [I6]", () => {
    render(<ContractPanel contract={contractOf("poisoned_bill.notary")} />);
    const chips = [...document.querySelectorAll<HTMLElement>("[data-param]")];
    expect(chips).toHaveLength(2);
    for (const chip of chips) {
      const tone = chip.getAttribute("data-tone");
      expect(["strict", "gated", "open"]).toContain(tone);
      expect(chip.getAttribute("data-marker-kind")).not.toBe("");
      expect(chip.nextElementSibling?.textContent).toBe(tone);
    }
  });

  it("shows the manifest pin as 8 characters with the full value in the title [I6]", () => {
    const contract = contractOf("poisoned_bill.notary");
    render(<ContractPanel contract={contract} />);
    const pay = must(
      contract.allowed_tools.find((t) => t.tool === "pay_bill"),
      "pay_bill scope",
    );
    const pin = must(tool("pay_bill").querySelector<HTMLElement>("[data-manifest]"), "pin");
    expect(pin.textContent).toBe(pay.manifest_hash.slice(0, 8));
    expect(pin.textContent).toHaveLength(8);
    expect(pin.getAttribute("title")).toBe(pay.manifest_hash);
  });
});

describe("ContractPanel empty and synthetic cases", () => {
  it('shows "no egress allowed" and "none" for an empty list, and keeps the label for null [A8]', () => {
    const contract = contractOf("poisoned_bill.notary");
    expect(contract.egress_hosts).toEqual([]);
    const { unmount } = render(
      <ContractPanel contract={{ ...contract, authorized_irreversible: [] }} />,
    );
    expect(screen.getByText("no egress allowed")).toBeTruthy();
    expect(screen.getByText("none")).toBeTruthy();
    expect(
      document.querySelector('[data-tool="pay_bill"]')?.hasAttribute("data-irreversible"),
    ).toBe(false);
    unmount();

    render(<ContractPanel contract={null} />);
    const root = screen.getByLabelText("Intent contract");
    expect(root.textContent).toBe("No contract yet");
    expect(screen.queryByLabelText("Allowed tools")).toBeNull();
  });

  it("lists egress hosts as chips [A8]", () => {
    const contract: IntentContract = {
      ...contractOf("poisoned_bill.notary"),
      egress_hosts: ["bank.example", "api.example"],
    };
    render(<ContractPanel contract={contract} />);
    const hosts = [...screen.getByLabelText("Egress hosts").querySelectorAll("li")];
    expect(hosts.map((h) => h.textContent)).toEqual(["bank.example", "api.example"]);
    expect(screen.queryByText("no egress allowed")).toBeNull();
  });

  it("follows the contract's order of tools and parameters, never sorting [I6]", () => {
    const base = contractOf("poisoned_bill.notary");
    const pay = must(
      base.allowed_tools.find((t) => t.tool === "pay_bill"),
      "pay_bill",
    );
    const reordered: IntentContract = {
      ...base,
      allowed_tools: [
        {
          ...pay,
          params: {
            payee: must(pay.params.payee, "payee"),
            amount: must(pay.params.amount, "amount"),
          },
        },
        ...base.allowed_tools.filter((t) => t.tool !== "pay_bill"),
      ],
    };
    render(<ContractPanel contract={reordered} />);
    expect(
      [...screen.getByLabelText("Allowed tools").children].map((li) =>
        li.getAttribute("data-tool"),
      ),
    ).toEqual(["pay_bill", "read_inbox"]);
    expect(
      [...tool("pay_bill").querySelectorAll("[data-param]")].map((n) =>
        n.getAttribute("data-param"),
      ),
    ).toEqual(["payee", "amount"]);
    cleanup();

    const flipped: IntentContract = {
      ...base,
      allowed_tools: base.allowed_tools.map((t) =>
        t.tool === "pay_bill"
          ? {
              ...t,
              params: {
                amount: must(t.params.amount, "amount"),
                payee: must(t.params.payee, "payee"),
              },
            }
          : t,
      ),
    };
    render(<ContractPanel contract={flipped} />);
    expect(
      [...tool("pay_bill").querySelectorAll("[data-param]")].map((n) =>
        n.getAttribute("data-param"),
      ),
    ).toEqual(["amount", "payee"]);
  });

  it("prints every marker kind with its real fields and tone [I2]", () => {
    const base = contractOf("poisoned_bill.notary");
    const pay = must(
      base.allowed_tools.find((t) => t.tool === "pay_bill"),
      "pay_bill",
    );
    const contract: IntentContract = {
      ...base,
      allowed_tools: [
        {
          ...pay,
          params: {
            iban: { kind: "literal", value: "DE89370400440532013000" },
            cents: { kind: "literal", value: 12000 },
            urgent: { kind: "literal", value: false },
            payee: { kind: "ledger", ledger: "payees" },
            memo: { kind: "named_source", source: "contacts" },
            note: { kind: "free" },
            approve: { kind: "endorse" },
          },
        },
      ],
    };
    render(<ContractPanel contract={contract} />);
    const text = (name: string) => param("pay_bill", name).textContent;
    expect(text("iban")).toBe("iban: literal:DE89370400440532013000");
    expect(text("cents")).toBe("cents: literal:12000");
    expect(text("urgent")).toBe("urgent: literal:false");
    expect(text("payee")).toBe("payee: ledger:payees");
    expect(text("memo")).toBe("memo: source:contacts");
    const tones = ["iban", "cents", "urgent", "payee", "memo", "note", "approve"].map((n) =>
      param("pay_bill", n).getAttribute("data-tone"),
    );
    expect(tones).toEqual(["strict", "strict", "strict", "strict", "strict", "open", "gated"]);
  });

  it("prints the budget exactly, without rounding or formatting [I2]", () => {
    const base = contractOf("poisoned_bill.notary");
    const budget = {
      max_approvals: 0,
      max_call_amount_cents: 123456789,
      max_effects: 7,
      max_egress_bytes: 1000000,
      max_spend_cents: 99,
    };
    render(<ContractPanel contract={{ ...base, budget }} />);
    const dl = screen.getByLabelText("Effect budget");
    for (const [field, value] of Object.entries(budget)) {
      const dt = must(
        [...dl.querySelectorAll("dt")].find((n) => n.textContent === field),
        field,
      );
      expect(dt.nextElementSibling?.textContent).toBe(String(value));
    }
    expect(dl.textContent).not.toMatch(/[,.]\d{3}/);
  });

  it("does not mutate a frozen contract [I6]", () => {
    const contract = deepFreeze(contractOf("legitimate_bill.notary"));
    expect(() => render(<ContractPanel contract={contract} />)).not.toThrow();
    expect(screen.getByTestId("intent")).toBeTruthy();
  });

  it("exports the helpers and the props type [I6]", () => {
    expect(typeof ui.markerLabel).toBe("function");
    expect(typeof ui.markerTone).toBe("function");
    const tone: ui.MarkerTone = ui.markerTone({ kind: "endorse" });
    const props: ui.ContractPanelProps = { contract: null };
    expect(tone).toBe("gated");
    expect(props.contract).toBeNull();
  });
});
