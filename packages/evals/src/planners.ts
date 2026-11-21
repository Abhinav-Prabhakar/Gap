import { GapError } from "gapmcp-core";
import type { ToolDescriptor } from "gapmcp-core";
import type {
  HttpPlannerOptions,
  MockPlannerResponses,
  Planner,
  PlannerInput,
  ToolChoice,
} from "./types";

const CHAT_COMPLETIONS_SUFFIX = "/chat/completions";

/**
 * A deterministic planner for tests. Pass an array to replay a fixed set of
 * choices in order, or a function to compute a choice from the input.
 *
 * Arrays are consumed once; asking for more choices than were configured
 * throws a clear {@link GapError} so an unexpected eval count cannot silently
 * reuse responses.
 */
export class MockPlanner implements Planner {
  readonly #responses: readonly ToolChoice[] | undefined;
  readonly #handler:
    | ((input: PlannerInput) => ToolChoice | Promise<ToolChoice>)
    | undefined;
  readonly #calls: PlannerInput[] = [];
  #cursor = 0;

  constructor(responses: MockPlannerResponses) {
    if (Array.isArray(responses)) {
      this.#responses = [...responses];
      this.#handler = undefined;
    } else if (typeof responses === "function") {
      this.#responses = undefined;
      this.#handler = responses;
    } else {
      throw new GapError("MockPlanner requires an array of responses or a function.", {
        code: "INVALID_INPUT",
      });
    }
  }

  /** Number of fixed responses left, or `Infinity` for a function planner. */
  get remaining(): number {
    return this.#responses ? this.#responses.length - this.#cursor : Number.POSITIVE_INFINITY;
  }

  /** Every input received so far, in call order. */
  get calls(): readonly PlannerInput[] {
    return this.#calls;
  }

  async choose(input: PlannerInput): Promise<ToolChoice> {
    this.#calls.push(input);

    if (this.#handler) {
      return this.#handler(input);
    }

    const responses = this.#responses ?? [];
    if (this.#cursor >= responses.length) {
      throw new GapError(
        `MockPlanner ran out of responses after ${responses.length} call(s). ` +
          "Add more responses or construct it with a function.",
        { code: "INTERNAL" },
      );
    }

    const response = responses[this.#cursor];
    this.#cursor += 1;
    if (!response) {
      throw new GapError("MockPlanner encountered an empty response.", { code: "INTERNAL" });
    }
    return { ...response };
  }
}

/**
 * Append `/chat/completions` unless the endpoint already names the complete
 * route. Trailing slashes are ignored.
 */
export function normalizeChatCompletionsEndpoint(endpoint: string): string {
  const trimmed = endpoint.trim().replace(/\/+$/, "");
  return trimmed.endsWith(CHAT_COMPLETIONS_SUFFIX)
    ? trimmed
    : `${trimmed}${CHAT_COMPLETIONS_SUFFIX}`;
}

function toFunctionTool(tool: ToolDescriptor): Record<string, unknown> {
  return {
    type: "function",
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.inputSchema,
    },
  };
}

function parseArguments(raw: unknown): unknown {
  if (typeof raw !== "string") return raw;
  const trimmed = raw.trim();
  if (trimmed === "") return undefined;
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    // Keep the raw text so reports show exactly what the model produced.
    return raw;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * A URL safe to put in an error message: no credentials, query string or
 * fragment, so a key embedded in the endpoint cannot leak.
 */
function displayEndpoint(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return "the configured endpoint";
  }
}

/**
 * Parse an OpenAI-compatible chat completion into a single tool choice.
 * Missing choices or tool calls mean "no tool"; malformed tool calls throw an
 * UNAVAILABLE error because the provider contract was violated.
 */
function readToolChoice(payload: unknown): ToolChoice {
  if (!isRecord(payload)) {
    throw new GapError("Eval planner response was not a JSON object.", { code: "UNAVAILABLE" });
  }

  const choices = payload.choices;
  if (!Array.isArray(choices)) {
    throw new GapError("Eval planner response did not contain a choices array.", {
      code: "UNAVAILABLE",
    });
  }
  if (choices.length === 0) return { tool: null };

  const first = choices[0];
  if (!isRecord(first)) return { tool: null };
  const message = first.message;
  if (!isRecord(message)) return { tool: null };

  const reasoning =
    typeof message.content === "string" && message.content.trim() !== ""
      ? message.content
      : undefined;
  const withReasoning = (choice: ToolChoice): ToolChoice =>
    reasoning === undefined ? choice : { ...choice, reasoning };

  const toolCalls = message.tool_calls;
  if (!Array.isArray(toolCalls) || toolCalls.length === 0) {
    return withReasoning({ tool: null });
  }

  const call = toolCalls[0];
  if (!isRecord(call)) {
    throw new GapError("Eval planner returned a malformed tool call.", { code: "UNAVAILABLE" });
  }
  const fn = call.function;
  if (!isRecord(fn)) {
    throw new GapError("Eval planner tool call had no function payload.", {
      code: "UNAVAILABLE",
    });
  }
  const name = fn.name;
  if (typeof name !== "string" || name.trim() === "") {
    throw new GapError("Eval planner tool call had no function name.", { code: "UNAVAILABLE" });
  }

  const args = parseArguments(fn.arguments);
  return withReasoning({
    tool: name,
    ...(args === undefined ? {} : { args }),
  });
}

/**
 * Create a planner backed by an OpenAI-compatible chat completions endpoint.
 *
 * The request uses `tool_choice: "auto"` and `temperature: 0`, maps registry
 * tools to function definitions, and parses the first returned tool call.
 * Non-2xx responses, transport failures and malformed payloads surface as
 * `GapError` with code `UNAVAILABLE`. The API key is only sent in the
 * `Authorization` header and is never echoed in errors.
 */
export function httpPlanner(options: HttpPlannerOptions): Planner {
  const endpoint = options.endpoint?.trim();
  if (!endpoint) {
    throw new GapError("httpPlanner requires a non-empty endpoint.", { code: "INVALID_INPUT" });
  }
  const model = options.model?.trim();
  if (!model) {
    throw new GapError("httpPlanner requires a non-empty model.", { code: "INVALID_INPUT" });
  }

  const url = normalizeChatCompletionsEndpoint(endpoint);
  const endpointLabel = displayEndpoint(url);
  const doFetch: typeof fetch =
    options.fetch ?? ((input, init) => globalThis.fetch(input, init));

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (options.apiKey) headers.Authorization = `Bearer ${options.apiKey}`;
  for (const [name, value] of Object.entries(options.headers ?? {})) {
    for (const existing of Object.keys(headers)) {
      if (existing.toLowerCase() === name.toLowerCase()) delete headers[existing];
    }
    headers[name] = value;
  }

  return {
    async choose(input: PlannerInput): Promise<ToolChoice> {
      const messages: Array<{ role: "system" | "user"; content: string }> = [];
      if (input.system !== undefined && input.system.trim() !== "") {
        messages.push({ role: "system", content: input.system });
      }
      messages.push({ role: "user", content: input.prompt });

      const body = {
        model,
        messages,
        tools: input.tools.map(toFunctionTool),
        tool_choice: "auto",
        temperature: 0,
      };

      let response: Response;
      try {
        response = await doFetch(url, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        });
      } catch {
        throw new GapError(
          `Eval planner request to ${endpointLabel} failed before a response was received.`,
          { code: "UNAVAILABLE" },
        );
      }

      if (!response.ok) {
        throw new GapError(
          `Eval planner request to ${endpointLabel} failed with HTTP ${response.status}.`,
          {
            code: "UNAVAILABLE",
            status: response.status,
            retryable: response.status === 429 || response.status >= 500,
          },
        );
      }

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new GapError(`Eval planner endpoint ${endpointLabel} returned invalid JSON.`, {
          code: "UNAVAILABLE",
        });
      }

      return readToolChoice(payload);
    },
  };
}
