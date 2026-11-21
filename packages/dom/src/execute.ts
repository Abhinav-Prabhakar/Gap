import { GapError, type ActionUiBinding } from "gapmcp-core";

/** Options for {@link executeUiAction}. */
export interface ExecuteUiActionOptions {
  document: Document;
  /** How long to wait for `waitFor`/`result` selectors. Defaults to 10s. */
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** Outcome of driving a bound UI flow. */
export interface ExecuteUiActionResult {
  ok: boolean;
  value?: string;
}

const DEFAULT_TIMEOUT_MS = 10_000;

function queryWithin(root: Element, selector: string): Element | null {
  if (selector.length === 0) return null;
  try {
    const match = root.querySelector(selector);
    if (match) return match;
    return root.matches(selector) ? root : null;
  } catch {
    return null;
  }
}

function queryDocument(doc: Document, selector: string): Element | null {
  if (selector.length === 0) return null;
  try {
    return doc.querySelector(selector);
  } catch {
    return null;
  }
}

function findRoot(doc: Document, actionId: string | undefined): HTMLElement | null {
  const nodes = doc.querySelectorAll("[data-gap-action]");
  for (const node of Array.from(nodes)) {
    if (actionId === undefined || node.getAttribute("data-gap-action") === actionId) {
      return node as HTMLElement;
    }
  }
  return null;
}

function setNativeValue(element: Element, property: string, value: unknown): void {
  let prototype: object | null = Object.getPrototypeOf(element) as object | null;
  while (prototype) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, property);
    if (descriptor?.set) {
      descriptor.set.call(element, value);
      return;
    }
    prototype = Object.getPrototypeOf(prototype) as object | null;
  }
  (element as unknown as Record<string, unknown>)[property] = value;
}

function toChecked(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true" || value === "on";
}

function dispatch(doc: Document, element: Element, type: string): void {
  const EventConstructor = doc.defaultView?.Event ?? globalThis.Event;
  if (typeof EventConstructor !== "function") return;
  element.dispatchEvent(new EventConstructor(type, { bubbles: true }));
}

function setFieldValue(doc: Document, element: Element, value: unknown): void {
  const candidate = element as HTMLElement & {
    type?: string;
    isContentEditable?: boolean;
  };
  if (candidate.isContentEditable) {
    candidate.textContent = value === undefined || value === null ? "" : String(value);
    dispatch(doc, element, "input");
    dispatch(doc, element, "change");
    return;
  }
  if (candidate.type === "checkbox" || candidate.type === "radio") {
    setNativeValue(element, "checked", toChecked(value));
    dispatch(doc, element, "input");
    dispatch(doc, element, "change");
    return;
  }
  setNativeValue(element, "value", value === undefined || value === null ? "" : String(value));
  dispatch(doc, element, "input");
  dispatch(doc, element, "change");
}

function fillFields(
  doc: Document,
  root: Element,
  binding: ActionUiBinding,
  args: Record<string, unknown>,
): void {
  const fields = binding.fields;
  if (!fields) return;
  for (const key of Object.keys(fields)) {
    if (!Object.prototype.hasOwnProperty.call(args, key)) continue;
    const selector = fields[key];
    if (typeof selector !== "string") continue;
    const element = queryWithin(root, selector);
    if (!element) continue;
    setFieldValue(doc, element, args[key]);
  }
}

function readResult(element: Element | null): string | undefined {
  if (!element) return undefined;
  const tag = element.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") {
    return String((element as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement).value);
  }
  return (element.textContent ?? "").trim();
}

function waitForElement(
  doc: Document,
  selector: string,
  timeoutMs: number,
  signal: AbortSignal | undefined,
): Promise<Element> {
  return new Promise<Element>((resolve, reject) => {
    const aborted = (): GapError =>
      new GapError("The UI action was aborted.", { code: "TIMEOUT" });
    if (signal?.aborted) {
      reject(aborted());
      return;
    }

    const existing = queryDocument(doc, selector);
    if (existing) {
      resolve(existing);
      return;
    }

    let settled = false;
    const cleanups: Array<() => void> = [];
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      for (const cleanup of cleanups) cleanup();
      action();
    };
    const check = (): void => {
      if (settled) return;
      const element = queryDocument(doc, selector);
      if (element) finish(() => resolve(element));
    };

    const timer = setTimeout(() => {
      finish(() =>
        reject(
          new GapError(`Timed out waiting for UI selector "${selector}".`, {
            code: "TIMEOUT",
          }),
        ),
      );
    }, timeoutMs);
    cleanups.push(() => clearTimeout(timer));

    if (signal) {
      const onAbort = (): void => finish(() => reject(aborted()));
      signal.addEventListener("abort", onAbort, { once: true });
      cleanups.push(() => signal.removeEventListener("abort", onAbort));
    }

    const Observer =
      doc.defaultView?.MutationObserver ??
      (globalThis as { MutationObserver?: typeof MutationObserver }).MutationObserver;

    if (Observer) {
      const observer = new Observer(check);
      observer.observe(doc.documentElement ?? doc, {
        childList: true,
        subtree: true,
        attributes: true,
        characterData: true,
      });
      cleanups.push(() => observer.disconnect());
    } else {
      const interval = setInterval(check, 25);
      cleanups.push(() => clearInterval(interval));
    }
    check();
  });
}

/**
 * Drive one semantic UI binding against a supplied `Document` (happy-dom in
 * tests, a live page in a browser adapter). Fills mapped fields with native
 * setters, dispatches `input`/`change`, clicks the submit control, waits for
 * `waitFor` and `result`, and returns the result text or field value.
 *
 * Throws `GapError` with code `NOT_FOUND` when no matching root exists.
 * Timeouts and aborts return `{ ok: false }`.
 */
export async function executeUiAction(
  binding: ActionUiBinding,
  args: Record<string, unknown>,
  options: ExecuteUiActionOptions,
): Promise<ExecuteUiActionResult> {
  const doc = options.document;
  const actionId =
    typeof binding.action === "string" && binding.action.length > 0
      ? binding.action
      : undefined;
  const root = findRoot(doc, actionId);
  if (!root) {
    const label = actionId ?? "(any)";
    throw new GapError(`No element matched data-gap-action="${label}".`, {
      code: "NOT_FOUND",
    });
  }

  if (options.signal?.aborted) return { ok: false };
  const timeoutMs =
    typeof options.timeoutMs === "number" &&
    Number.isFinite(options.timeoutMs) &&
    options.timeoutMs > 0
      ? Math.floor(options.timeoutMs)
      : DEFAULT_TIMEOUT_MS;

  try {
    fillFields(doc, root, binding, args);

    let target: Element = root;
    if (binding.submit) {
      const submit = queryWithin(root, binding.submit) ?? queryDocument(doc, binding.submit);
      if (submit) target = submit;
    }
    const clickable = target as HTMLElement;
    if (typeof clickable.click !== "function") return { ok: false };
    clickable.click();

    if (binding.waitFor) {
      await waitForElement(doc, binding.waitFor, timeoutMs, options.signal);
    }
    let resultElement: Element | null = null;
    if (binding.result) {
      resultElement = await waitForElement(doc, binding.result, timeoutMs, options.signal);
    }

    const value = readResult(resultElement);
    return value === undefined ? { ok: true } : { ok: true, value };
  } catch {
    return { ok: false };
  }
}
