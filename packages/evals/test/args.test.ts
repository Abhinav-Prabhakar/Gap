import { describe, expect, it } from "vitest";
import { scoreArgs } from "../src/index";

describe("scoreArgs", () => {
  it("matches nested objects as a subset and reports top-level extras", () => {
    const result = scoreArgs(
      { filter: { status: "open", tags: ["a", "b"] } },
      { filter: { status: "open", tags: ["a", "b"], page: 2 }, limit: 10 },
    );

    expect(result).toEqual({ passed: true, missingArgs: [], extraArgs: ["limit"] });
  });

  it("reports missing nested paths", () => {
    const result = scoreArgs(
      { filter: { status: "open", owner: "me" } },
      { filter: { status: "open" } },
    );

    expect(result.passed).toBe(false);
    expect(result.missingArgs).toEqual(["filter.owner"]);
    expect(result.extraArgs).toEqual([]);
  });

  it("reports a wholly missing object once and lists every root key when actual is not an object", () => {
    expect(scoreArgs({ filter: { status: "open" } }, {}).missingArgs).toEqual(["filter"]);
    expect(scoreArgs({ b: 2, a: 1 }, null).missingArgs).toEqual(["a", "b"]);
  });

  it("reports primitive mismatches as missing expected paths", () => {
    const result = scoreArgs({ status: "open", total: 10 }, { status: "closed", total: 10 });
    expect(result.passed).toBe(false);
    expect(result.missingArgs).toEqual(["status"]);
  });

  it("requires arrays to match exactly", () => {
    expect(scoreArgs({ tags: ["a", "b"] }, { tags: ["a", "b"] }).passed).toBe(true);
    expect(scoreArgs({ tags: ["a", "b"] }, { tags: ["b", "a"] }).missingArgs).toEqual(["tags"]);
    expect(scoreArgs({ tags: ["a"] }, { tags: ["a", "b"] }).passed).toBe(false);
    expect(scoreArgs({ tags: [] }, { tags: [] }).passed).toBe(true);
  });

  it("passes any argument shape when no expectation is provided", () => {
    expect(scoreArgs(undefined, { anything: true })).toEqual({
      passed: true,
      missingArgs: [],
      extraArgs: [],
    });
    expect(scoreArgs(undefined, undefined).passed).toBe(true);
  });

  it("ignores object key order but treats extra nested keys as compatible", () => {
    expect(
      scoreArgs({ customer: { id: "cus_1", name: "Ada" } }, { customer: { name: "Ada", id: "cus_1" } })
        .passed,
    ).toBe(true);
    expect(
      scoreArgs({ customer: { id: "cus_1" } }, { customer: { id: "cus_1", name: "Ada" } }).passed,
    ).toBe(true);
  });
});
