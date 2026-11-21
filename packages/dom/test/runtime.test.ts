// @vitest-environment happy-dom

import { beforeEach, describe, expect, it } from "vitest";
import { GapError } from "gapmcp-core";
import {
  renderDomRuntime,
  renderDomScriptTag,
  type DomActionBinding,
} from "../src/index.js";

interface GapRuntime {
  actions: unknown;
  call(
    name: string,
    args?: Record<string, unknown>,
  ): Promise<{ ok: boolean; value?: string; error?: string }>;
}

function runtimeGlobal(name = "Gap"): GapRuntime | undefined {
  return (window as unknown as Record<string, GapRuntime | undefined>)[name];
}

const BINDING: DomActionBinding = {
  name: "invoices.create",
  scopes: ["invoices:write"],
  risk: "medium",
  ui: {
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
  },
};

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

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("renderDomRuntime", () => {
  it("emits a dependency-free runtime with actions and call", () => {
    const runtime = renderDomRuntime({ actions: [BINDING] });
    expect(runtime).toContain("data-gap-action");
    expect(runtime).toContain("async function call");
    expect(runtime).toContain("actions: initialActions");
    expect(runtime).toContain("MutationObserver");
    expect(runtime).toContain("scope[globalName] = api");
  });

  it("supports a custom global name and rejects unsafe names", () => {
    const runtime = renderDomRuntime({ globalName: "MyGap", timeoutMs: 250 });
    expect(runtime).toContain('var globalName = "MyGap"');
    expect(runtime).toContain("var timeoutMs = 250");
    expect(() => renderDomRuntime({ globalName: "bad name" })).toThrow(
      GapError,
    );
    expect(() => renderDomRuntime({ globalName: 'x"];alert(1)//' })).toThrow(
      GapError,
    );
  });

  it("escapes action names so they cannot break out of a script tag", () => {
    const evil = "</script><script>window.__gapPwned = true</script>";
    const action: DomActionBinding = {
      name: evil,
      scopes: [],
      risk: "low",
      ui: { action: evil },
    };
    const runtime = renderDomRuntime({ actions: [action] });
    expect(runtime).not.toContain("</script");
    expect(runtime).toContain("\\u003c/script");

    const tag = renderDomScriptTag({ actions: [action] });
    expect(tag.match(/<\/script>/g)).toHaveLength(1);
    expect(tag).not.toContain("window.__gapPwned = true</script>");
  });

  it("fills fields, clicks submit, waits for a result, and returns it", async () => {
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
      }, 10);
    });
    const customer = document.querySelector<HTMLInputElement>(
      'input[name="customer"]',
    );
    customer?.addEventListener("input", () => {
      inputEvents += 1;
    });
    customer?.addEventListener("change", () => {
      changeEvents += 1;
    });

    new Function(renderDomRuntime({ actions: [BINDING], timeoutMs: 1_000 }))();
    const gap = runtimeGlobal();
    expect(gap).toBeDefined();

    const outcome = await gap!.call("invoices.create", {
      customer: "Ada",
      currency: "eur",
      note: "Net 30",
      memo: "urgent",
      notify: true,
    });

    expect(outcome).toEqual({
      ok: true,
      value: "Ada|eur|Net 30|urgent|notify",
    });
    expect(inputEvents).toBeGreaterThan(0);
    expect(changeEvents).toBeGreaterThan(0);
    expect(
      document.querySelector<HTMLInputElement>('input[name="customer"]')?.value,
    ).toBe("Ada");
  });

  it("throws for unknown actions and returns an error when the root is missing", async () => {
    new Function(renderDomRuntime({ actions: [BINDING], timeoutMs: 200 }))();
    const gap = runtimeGlobal()!;

    await expect(gap.call("unknown.action")).rejects.toThrow(
      /Unknown Gap action/,
    );

    document.body.innerHTML = "<div>nothing to see</div>";
    await expect(gap.call("invoices.create")).resolves.toMatchObject({
      ok: false,
    });
  });

  it("accepts actions assigned after the runtime is installed", async () => {
    installForm((result) => {
      result.textContent = "late binding";
    });
    new Function(renderDomRuntime({ timeoutMs: 500 }))();
    const gap = runtimeGlobal()!;
    gap.actions = [BINDING];

    await expect(
      gap.call("invoices.create", { customer: "Grace" }),
    ).resolves.toEqual({
      ok: true,
      value: "late binding",
    });
  });

  it("can synthesize a minimal binding for a root already in the page", async () => {
    document.body.innerHTML = `
      <button data-gap-action="direct.run">Run</button>
    `;
    let clicked = 0;
    document.querySelector("button")?.addEventListener("click", () => {
      clicked += 1;
    });
    new Function(renderDomRuntime({ timeoutMs: 500 }))();
    const gap = runtimeGlobal()!;

    await expect(gap.call("direct.run")).resolves.toEqual({ ok: true });
    expect(clicked).toBe(1);
  });
});
