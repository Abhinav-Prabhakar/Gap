// @vitest-environment happy-dom

import { beforeEach, describe, expect, it } from "vitest";
import { GapError } from "gapmcp-core";
import { executeUiAction, type ExecuteUiActionResult } from "../src/index.js";

beforeEach(() => {
  document.body.innerHTML = "";
});

function installForm(handler: (result: HTMLElement) => void): void {
  document.body.innerHTML = `
    <div data-gap-action="invoice-create">
      <input name="customer" />
      <select name="currency">
        <option value="usd">USD</option>
        <option value="eur">EUR</option>
      </select>
      <textarea name="note"></textarea>
      <div contenteditable="true" data-memo></div>
      <input type="checkbox" name="notify" />
      <button type="submit">Create</button>
      <div data-result></div>
    </div>
  `;
  const button = document.querySelector("button");
  const result = document.querySelector<HTMLElement>("[data-result]");
  if (!button || !result) throw new Error("Fixture is incomplete");
  button.addEventListener("click", (event) => {
    event.preventDefault();
    handler(result);
  });
}

const BINDING = {
  action: "invoice-create",
  fields: {
    customer: 'input[name="customer"]',
    currency: 'select[name="currency"]',
    note: 'textarea[name="note"]',
    memo: "[data-memo]",
    notify: 'input[name="notify"]',
  },
  submit: 'button[type="submit"]',
  result: "[data-result]",
} as const;

describe("executeUiAction", () => {
  it("fills fields, clicks submit, and reads the result", async () => {
    let inputEvents = 0;
    let changeEvents = 0;
    installForm((result) => {
      setTimeout(() => {
        const customer = document.querySelector<HTMLInputElement>(
          'input[name="customer"]',
        );
        const currency = document.querySelector<HTMLSelectElement>(
          'select[name="currency"]',
        );
        const note = document.querySelector<HTMLTextAreaElement>(
          'textarea[name="note"]',
        );
        const memo = document.querySelector<HTMLElement>("[data-memo]");
        const notify = document.querySelector<HTMLInputElement>(
          'input[name="notify"]',
        );
        result.textContent = [
          customer?.value,
          currency?.value,
          note?.value,
          memo?.textContent,
          notify?.checked ? "notify" : "quiet",
        ].join("|");
      }, 5);
    });
    document
      .querySelector('input[name="customer"]')
      ?.addEventListener("input", () => {
        inputEvents += 1;
      });
    document
      .querySelector('input[name="customer"]')
      ?.addEventListener("change", () => {
        changeEvents += 1;
      });

    const outcome = await executeUiAction(
      BINDING,
      {
        customer: "Ada",
        currency: "eur",
        note: "Net 30",
        memo: "urgent",
        notify: true,
      },
      { document, timeoutMs: 1_000 },
    );

    expect(outcome).toEqual({
      ok: true,
      value: "Ada|eur|Net 30|urgent|notify",
    });
    expect(inputEvents).toBeGreaterThan(0);
    expect(changeEvents).toBeGreaterThan(0);
    expect(
      document.querySelector<HTMLInputElement>('input[name="customer"]')?.value,
    ).toBe("Ada");
    expect(
      document.querySelector<HTMLSelectElement>('select[name="currency"]')
        ?.value,
    ).toBe("eur");
    expect(
      document.querySelector<HTMLInputElement>('input[name="notify"]')?.checked,
    ).toBe(true);
  });

  it("reads a result published through an input's value property", async () => {
    document.body.innerHTML = `
      <div data-gap-action="lookup">
        <button type="submit">Look up</button>
        <input name="result" />
      </div>
    `;
    document.querySelector("button")?.addEventListener("click", () => {
      setTimeout(() => {
        document.querySelector<HTMLInputElement>(
          'input[name="result"]',
        )!.value = "found:42";
      }, 10);
    });

    const outcome = await executeUiAction(
      { action: "lookup", submit: "button", result: 'input[name="result"]' },
      {},
      { document, timeoutMs: 1_000 },
    );
    expect(outcome).toEqual({ ok: true, value: "found:42" });
  });

  it("waits for a waitFor selector before reading the result", async () => {
    document.body.innerHTML = `
      <div data-gap-action="slow">
        <button type="submit">Run</button>
        <div class="status"></div>
      </div>
    `;
    document.querySelector("button")?.addEventListener("click", () => {
      setTimeout(() => {
        const status = document.querySelector(".status");
        if (!status) return;
        status.setAttribute("data-ready", "true");
        status.textContent = "finished";
      }, 10);
    });

    const outcome = await executeUiAction(
      {
        action: "slow",
        submit: "button",
        waitFor: "[data-ready]",
        result: ".status",
      },
      {},
      { document, timeoutMs: 1_000 },
    );
    expect(outcome).toEqual({ ok: true, value: "finished" });
  });

  it("falls back to the root element as the click target", async () => {
    document.body.innerHTML = `<div data-gap-action="root-only">Idle</div>`;
    let clicked = 0;
    document
      .querySelector("[data-gap-action]")
      ?.addEventListener("click", (event) => {
        clicked += 1;
        (event.currentTarget as HTMLElement).textContent = "clicked";
      });

    const outcome = await executeUiAction(
      { action: "root-only", result: "[data-gap-action]" },
      {},
      { document, timeoutMs: 500 },
    );
    expect(outcome).toEqual({ ok: true, value: "clicked" });
    expect(clicked).toBe(1);
  });

  it("uses the first root when the binding has no action id", async () => {
    document.body.innerHTML = `
      <div data-gap-action="first">
        <input name="name" />
        <button>Go</button>
      </div>
    `;
    document.querySelector("button")?.addEventListener("click", () => {
      const input =
        document.querySelector<HTMLInputElement>('input[name="name"]');
      (document.querySelector("[data-gap-action]") as HTMLElement).textContent =
        `hello ${input?.value}`;
    });

    const outcome = await executeUiAction(
      {
        fields: { name: 'input[name="name"]' },
        submit: "button",
        result: "[data-gap-action]",
      },
      { name: "Ada" },
      { document, timeoutMs: 500 },
    );
    expect(outcome).toEqual({ ok: true, value: "hello Ada" });
  });

  it("throws GapError NOT_FOUND when the root is missing", async () => {
    await expect(
      executeUiAction({ action: "missing", fields: {} }, {}, { document }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("returns ok:false when the result selector never appears", async () => {
    document.body.innerHTML = `
      <div data-gap-action="timeout">
        <button type="submit">Run</button>
      </div>
    `;

    const outcome = await executeUiAction(
      { action: "timeout", submit: "button", result: "[data-never]" },
      {},
      { document, timeoutMs: 30 },
    );
    expect(outcome).toEqual({ ok: false });
  });

  it("returns ok:false when the signal is already aborted", async () => {
    document.body.innerHTML = `<div data-gap-action="aborted"><button>Run</button></div>`;
    const controller = new AbortController();
    controller.abort();

    const outcome = await executeUiAction(
      { action: "aborted", submit: "button" },
      {},
      { document, signal: controller.signal },
    );
    expect(outcome).toEqual({ ok: false });
  });

  it("stops waiting when the signal aborts", async () => {
    document.body.innerHTML = `<div data-gap-action="aborted-later"><button>Run</button></div>`;
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 5);

    const started = Date.now();
    const outcome = await executeUiAction(
      { action: "aborted-later", submit: "button", result: "[data-never]" },
      {},
      { document, timeoutMs: 5_000, signal: controller.signal },
    );
    expect(outcome).toEqual({ ok: false });
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("skips missing fields instead of failing the flow", async () => {
    document.body.innerHTML = `
      <div data-gap-action="skip">
        <input name="present" />
        <button>Run</button>
      </div>
    `;
    document.querySelector("button")?.addEventListener("click", () => {
      const present = document.querySelector<HTMLInputElement>(
        'input[name="present"]',
      );
      (document.querySelector("[data-gap-action]") as HTMLElement).textContent =
        present?.value ?? "";
    });

    const outcome: ExecuteUiActionResult = await executeUiAction(
      {
        action: "skip",
        fields: {
          present: 'input[name="present"]',
          absent: 'input[name="absent"]',
        },
        submit: "button",
        result: "[data-gap-action]",
      },
      { present: "yes", absent: "ignored" },
      { document, timeoutMs: 500 },
    );
    expect(outcome).toEqual({ ok: true, value: "yes" });
  });
});
