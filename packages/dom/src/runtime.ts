import { GapError } from "gapmcp-core";
import type { DomActionBinding } from "./manifest.js";

/** Options for {@link renderDomRuntime} and {@link renderDomScriptTag}. */
export interface DomRuntimeOptions {
  /** Global object to create. Defaults to `Gap`. Must be a valid identifier. */
  globalName?: string;
  /** How long `call` waits for `waitFor` and `result` selectors. Defaults to 10s. */
  timeoutMs?: number;
  /**
   * Action bindings embedded in the runtime. They may also be assigned later:
   * `window.Gap.actions = manifest.actions`.
   */
  actions?: readonly DomActionBinding[];
}

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const DEFAULT_TIMEOUT_MS = 10_000;

function escapeForInlineScript(json: string): string {
  return json
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/**
 * Render a dependency-free IIFE that exposes `{ actions, call }` on a global.
 *
 * `call(name, args)` finds `[data-gap-action="<binding.ui.action ?? name>"]`,
 * fills mapped fields with native setters (so React sees the change), clicks
 * the submit control, waits for `waitFor`/`result`, and returns
 * `{ ok: true, value }` or `{ ok: false, error }`. Unknown actions throw.
 */
export function renderDomRuntime(options: DomRuntimeOptions = {}): string {
  const globalName = options.globalName ?? "Gap";
  if (!IDENTIFIER.test(globalName)) {
    throw new GapError(
      `Invalid DOM runtime global name "${globalName}". Use a JavaScript identifier such as "Gap".`,
      { code: "INVALID_INPUT" },
    );
  }
  const timeoutMs =
    typeof options.timeoutMs === "number" &&
    Number.isFinite(options.timeoutMs) &&
    options.timeoutMs > 0
      ? Math.floor(options.timeoutMs)
      : DEFAULT_TIMEOUT_MS;
  const actions = escapeForInlineScript(JSON.stringify(options.actions ?? []));

  return `(function () {
  "use strict";
  var globalName = ${JSON.stringify(globalName)};
  var timeoutMs = ${timeoutMs};
  var initialActions = ${actions};
  var scope = typeof window !== "undefined" ? window : globalThis;
  var api = { actions: initialActions, call: call };

  function findRoot(actionId) {
    var wanted = String(actionId);
    var nodes = document.querySelectorAll("[data-gap-action]");
    for (var index = 0; index < nodes.length; index += 1) {
      if (nodes[index].getAttribute("data-gap-action") === wanted) return nodes[index];
    }
    return null;
  }

  function lookup(name) {
    var list = api.actions;
    var index;
    if (Array.isArray(list)) {
      for (index = 0; index < list.length; index += 1) {
        var item = list[index];
        if (item && (item.name === name || (item.ui && item.ui.action === name))) return item;
      }
    } else if (list && typeof list === "object") {
      if (list[name]) return list[name];
      var keys = Object.keys(list);
      for (index = 0; index < keys.length; index += 1) {
        var candidate = list[keys[index]];
        if (candidate && candidate.ui && candidate.ui.action === name) return candidate;
      }
    }
    if (findRoot(name)) return { name: name, scopes: [], risk: "low", ui: { action: name } };
    return null;
  }

  function setNative(element, property, value) {
    var proto = Object.getPrototypeOf(element);
    while (proto) {
      var descriptor = Object.getOwnPropertyDescriptor(proto, property);
      if (descriptor && descriptor.set) {
        descriptor.set.call(element, value);
        return;
      }
      proto = Object.getPrototypeOf(proto);
    }
    element[property] = value;
  }

  function fire(element, type) {
    var view = element.ownerDocument && element.ownerDocument.defaultView;
    var EventCtor = (view && view.Event) || Event;
    element.dispatchEvent(new EventCtor(type, { bubbles: true }));
  }

  function toChecked(value) {
    return value === true || value === 1 || value === "1" || value === "true" || value === "on";
  }

  function fill(root, binding, args) {
    var fields = binding && binding.ui && binding.ui.fields ? binding.ui.fields : {};
    var keys = Object.keys(fields);
    for (var index = 0; index < keys.length; index += 1) {
      var key = keys[index];
      if (!args || !Object.prototype.hasOwnProperty.call(args, key)) continue;
      var selector = fields[key];
      var element = null;
      try { element = root.querySelector(selector); } catch (error) { element = null; }
      if (element === null && root.matches) {
        try { if (root.matches(selector)) element = root; } catch (error) { element = null; }
      }
      if (!element) continue;
      var value = args[key];
      if (element.isContentEditable) {
        element.textContent = value === undefined || value === null ? "" : String(value);
        fire(element, "input");
        fire(element, "change");
        continue;
      }
      if (element.type === "checkbox" || element.type === "radio") {
        setNative(element, "checked", toChecked(value));
        fire(element, "input");
        fire(element, "change");
        continue;
      }
      setNative(element, "value", value === undefined || value === null ? "" : String(value));
      fire(element, "input");
      fire(element, "change");
    }
  }

  function readValue(element) {
    if (!element) return undefined;
    var tag = element.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return String(element.value);
    return String(element.textContent || "").trim();
  }

  function waitForElement(selector) {
    var existing = null;
    try { existing = document.querySelector(selector); } catch (error) { existing = null; }
    if (existing) return Promise.resolve(existing);
    return new Promise(function (resolve, reject) {
      var settled = false;
      var observer = new MutationObserver(check);
      var timer = setTimeout(function () {
        if (settled) return;
        settled = true;
        observer.disconnect();
        reject(new Error("Timed out waiting for " + selector));
      }, timeoutMs);
      function finish(element) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        observer.disconnect();
        resolve(element);
      }
      function check() {
        if (settled) return;
        var element = null;
        try { element = document.querySelector(selector); } catch (error) { element = null; }
        if (element) finish(element);
      }
      observer.observe(document.documentElement || document, {
        childList: true,
        subtree: true,
        attributes: true,
        characterData: true
      });
      check();
    });
  }

  async function call(name, args) {
    var input = args || {};
    var binding = lookup(name);
    if (!binding) throw new Error("Unknown Gap action: " + name);
    var ui = binding.ui || {};
    var actionId = ui.action || binding.name || name;
    var root = findRoot(actionId);
    if (!root) {
      return { ok: false, error: "No element with data-gap-action=\\"" + actionId + "\\" was found." };
    }
    fill(root, binding, input);
    var target = root;
    if (ui.submit) {
      try {
        var submit = root.querySelector(ui.submit) || document.querySelector(ui.submit);
        if (submit) target = submit;
      } catch (error) {
        // Leave the root as the click target when the selector is invalid.
      }
    }
    if (typeof target.click !== "function") {
      return { ok: false, error: "The matched UI root cannot be clicked." };
    }
    target.click();
    try {
      if (ui.waitFor) await waitForElement(ui.waitFor);
      var resultElement = ui.result ? await waitForElement(ui.result) : null;
      var value = readValue(resultElement);
      return value === undefined ? { ok: true } : { ok: true, value: value };
    } catch (error) {
      return { ok: false, error: error && error.message ? error.message : String(error) };
    }
  }

  scope[globalName] = api;
})();`;
}

/** Wrap {@link renderDomRuntime} in a `<script>` element string. */
export function renderDomScriptTag(options: DomRuntimeOptions = {}): string {
  return `<script>${renderDomRuntime(options)}</script>`;
}
