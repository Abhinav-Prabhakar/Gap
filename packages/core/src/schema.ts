import { z } from "zod";
import Ajv2020 from "ajv/dist/2020.js";
import type { JsonSchema, SchemaLike, ValidationIssue, ValidationResult } from "./types";
import { GapError, invalidInput } from "./errors";

type JsonSchemaIo = "input" | "output";

const ajv = new Ajv2020({
  strict: false,
  allErrors: true,
  allowUnionTypes: true,
  validateFormats: false,
  discriminator: true,
});

const compiled = new WeakMap<object, ReturnType<typeof ajv.compile>>();

/** Zod v4 instances carry `_zod`; accept anything that behaves like a schema. */
export function isZodSchema(value: unknown): value is z.ZodType {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as { _zod?: unknown; safeParse?: unknown };
  return typeof candidate.safeParse === "function" && candidate._zod !== undefined;
}

export function isJsonSchema(value: unknown): value is JsonSchema {
  return typeof value === "object" && value !== null;
}

function cleanSchema(schema: JsonSchema): JsonSchema {
  const { $schema: _schema, $id: _id, ...rest } = schema;
  return rest;
}

/**
 * Convert either schema representation to JSON Schema. Zod schemas are
 * converted with input/output direction so optional/default handling matches
 * what the action actually receives.
 */
export function toJsonSchema(
  schema: SchemaLike | undefined,
  io: JsonSchemaIo = "input",
): JsonSchema | undefined {
  if (!schema) return undefined;
  if (!isZodSchema(schema)) return cleanSchema(schema);

  try {
    const converted = z.toJSONSchema(schema, {
      target: "draft-2020-12",
      io,
      unrepresentable: "any",
    }) as JsonSchema;
    return cleanSchema(converted);
  } catch (error) {
    throw new GapError("Failed to convert a Zod schema to JSON Schema.", {
      code: "INTERNAL",
      cause: error,
      expose: false,
    });
  }
}

export function toInputJsonSchema(schema: SchemaLike | undefined): JsonSchema {
  const converted = toJsonSchema(schema, "input");
  if (!converted) return { type: "object", properties: {}, additionalProperties: false };
  // MCP requires an object schema for tool input.
  if (converted.type === undefined) {
    return { ...converted, type: "object" };
  }
  return converted;
}

export function toOutputJsonSchema(schema: SchemaLike | undefined): JsonSchema | undefined {
  return toJsonSchema(schema, "output");
}

function issuesFromZod(error: z.ZodError): ValidationIssue[] {
  return error.issues.map((issue) => ({
    path: issue.path.length ? issue.path.join(".") : "(root)",
    message: issue.message,
    code: issue.code,
  }));
}

function issuesFromAjv(errors: readonly unknown[] | null | undefined): ValidationIssue[] {
  if (!errors || errors.length === 0) {
    return [{ path: "(root)", message: "Value does not match the schema." }];
  }
  return errors.map((raw) => {
    const error = raw as { instancePath?: string; message?: string; keyword?: string };
    return {
      path: error.instancePath ? error.instancePath.replace(/^\//, "").replace(/\//g, ".") : "(root)",
      message: error.message ?? "Invalid value.",
      code: error.keyword,
    };
  });
}

function validateJsonSchema(schema: JsonSchema, value: unknown): ValidationIssue[] | undefined {
  let validate = compiled.get(schema);
  if (!validate) {
    validate = ajv.compile(schema);
    compiled.set(schema, validate);
  }
  if (validate(value)) return undefined;
  return issuesFromAjv(validate.errors);
}

/**
 * Validate a value against either schema representation. Returns issues rather
 * than throwing so callers can shape the transport-specific error.
 */
export function validateValue<T = unknown>(
  schema: SchemaLike | undefined,
  value: unknown,
): ValidationResult<T> {
  if (!schema) return { success: true, data: value as T };

  if (isZodSchema(schema)) {
    const result = schema.safeParse(value);
    if (result.success) return { success: true, data: result.data as T };
    return { success: false, issues: issuesFromZod(result.error) };
  }

  const issues = validateJsonSchema(schema, value);
  if (!issues) return { success: true, data: value as T };
  return { success: false, issues };
}

/** Validate or throw a GapError with structured issues. */
export function parseValue<T = unknown>(
  schema: SchemaLike | undefined,
  value: unknown,
  label = "input",
): T {
  const result = validateValue<T>(schema, value);
  if (result.success) return result.data;
  throw invalidInput(`Invalid ${label}.`, { issues: result.issues });
}

/** True when the schema describes an object-shaped MCP tool input. */
export function isObjectSchema(schema: JsonSchema): boolean {
  return schema.type === "object" || (schema.type === undefined && typeof schema.properties === "object");
}

/** Collect property names that lack a description, used by the linter. */
export function schemaPathsWithoutDescriptions(schema: JsonSchema, prefix = ""): string[] {
  const missing: string[] = [];
  const properties = schema.properties as Record<string, JsonSchema> | undefined;
  if (properties) {
    for (const [key, property] of Object.entries(properties)) {
      const path = prefix ? `${prefix}.${key}` : key;
      if (typeof property.description !== "string" || property.description.trim() === "") {
        missing.push(path);
      }
      if (property.type === "object") missing.push(...schemaPathsWithoutDescriptions(property, path));
      if (property.type === "array" && property.items) {
        missing.push(...schemaPathsWithoutDescriptions(property.items as JsonSchema, `${path}[]`));
      }
    }
  }
  return missing;
}
