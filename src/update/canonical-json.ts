import { canonicalize } from "@tufjs/canonical-json";
import { UpdateError, type UpdateErrorCode } from "./errors.js";

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export const MAX_TUF_METADATA_BYTES = 256 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_VALUES = 100_000;

export interface CanonicalJsonOptions {
  readonly maxBytes?: number;
  readonly errorCode?: UpdateErrorCode;
}

/**
 * Parses one canonical JSON value without delegating key handling to JSON.parse.
 * Duplicate object keys are therefore rejected before any signature is interpreted.
 */
export function parseCanonicalJson(
  bytes: Uint8Array,
  options: CanonicalJsonOptions = {},
): JsonValue {
  const errorCode = options.errorCode ?? "GOAT_UPDATE_MANIFEST_INVALID";
  const maxBytes = options.maxBytes ?? MAX_TUF_METADATA_BYTES;
  if (bytes.byteLength === 0 || bytes.byteLength > maxBytes) {
    throw new UpdateError(
      bytes.byteLength > maxBytes
        ? "GOAT_UPDATE_MANIFEST_TOO_LARGE"
        : errorCode,
    );
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bytes,
    );
  } catch (error) {
    throw new UpdateError(errorCode, { cause: error });
  }
  if (text.charCodeAt(0) === 0xfeff) {
    throw new UpdateError(errorCode);
  }

  const parser = new StrictJsonParser(text, errorCode);
  const value = parser.parse();
  let canonical: string;
  try {
    canonical = canonicalize(value);
  } catch (error) {
    throw new UpdateError(errorCode, { cause: error });
  }
  if (canonical !== text) {
    throw new UpdateError(errorCode);
  }
  return value;
}

export function canonicalJson(value: JsonValue): string {
  try {
    return canonicalize(value);
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID", { cause: error });
  }
}

export function canonicalJsonBytes(value: JsonValue): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

export function isJsonObject(value: JsonValue | unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function hasExactJsonKeys(
  value: JsonObject,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  const actual = Object.keys(value);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    actual.every((key) => allowed.has(key))
  );
}

class StrictJsonParser {
  private index = 0;
  private valueCount = 0;

  constructor(
    private readonly source: string,
    private readonly errorCode: UpdateErrorCode,
  ) {}

  parse(): JsonValue {
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.source.length) this.fail();
    return value;
  }

  private parseValue(depth: number): JsonValue {
    this.valueCount += 1;
    if (depth > MAX_JSON_DEPTH || this.valueCount > MAX_JSON_VALUES)
      this.fail();
    this.skipWhitespace();
    const character = this.source[this.index];
    if (character === "{") return this.parseObject(depth + 1);
    if (character === "[") return this.parseArray(depth + 1);
    if (character === '"') return this.parseString();
    if (character === "t") return this.parseLiteral("true", true);
    if (character === "f") return this.parseLiteral("false", false);
    if (character === "n") return this.parseLiteral("null", null);
    if (character === "-" || isDigit(character)) return this.parseNumber();
    return this.fail();
  }

  private parseObject(depth: number): JsonObject {
    this.index += 1;
    const result: JsonObject = {};
    const keys = new Set<string>();
    this.skipWhitespace();
    if (this.source[this.index] === "}") {
      this.index += 1;
      return result;
    }

    while (this.index < this.source.length) {
      this.skipWhitespace();
      if (this.source[this.index] !== '"') this.fail();
      const key = this.parseString();
      if (keys.has(key)) this.fail();
      keys.add(key);
      this.skipWhitespace();
      if (this.source[this.index] !== ":") this.fail();
      this.index += 1;
      Object.defineProperty(result, key, {
        value: this.parseValue(depth),
        enumerable: true,
        writable: true,
        configurable: true,
      });
      this.skipWhitespace();
      const delimiter = this.source[this.index];
      if (delimiter === "}") {
        this.index += 1;
        return result;
      }
      if (delimiter !== ",") this.fail();
      this.index += 1;
    }
    return this.fail();
  }

  private parseArray(depth: number): JsonValue[] {
    this.index += 1;
    const result: JsonValue[] = [];
    this.skipWhitespace();
    if (this.source[this.index] === "]") {
      this.index += 1;
      return result;
    }
    while (this.index < this.source.length) {
      result.push(this.parseValue(depth));
      this.skipWhitespace();
      const delimiter = this.source[this.index];
      if (delimiter === "]") {
        this.index += 1;
        return result;
      }
      if (delimiter !== ",") this.fail();
      this.index += 1;
    }
    return this.fail();
  }

  private parseString(): string {
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.source.length) {
      const code = this.source.charCodeAt(this.index);
      const character = this.source[this.index];
      if (!escaped && character === '"') {
        this.index += 1;
        let decoded: unknown;
        try {
          decoded = JSON.parse(this.source.slice(start, this.index));
        } catch {
          return this.fail();
        }
        if (typeof decoded !== "string" || hasUnpairedSurrogate(decoded)) {
          return this.fail();
        }
        return decoded;
      }
      if (!escaped && code < 0x20) return this.fail();
      if (!escaped && character === "\\") {
        escaped = true;
        this.index += 1;
        continue;
      }
      if (escaped) {
        if (!'"\\/bfnrtu'.includes(character)) return this.fail();
        if (character === "u") {
          const hex = this.source.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) return this.fail();
          this.index += 4;
        }
        escaped = false;
      }
      this.index += 1;
    }
    return this.fail();
  }

  private parseNumber(): number {
    const remainder = this.source.slice(this.index);
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      remainder,
    );
    if (!match) return this.fail();
    this.index += match[0].length;
    const value = Number(match[0]);
    // TUF and every GOAT custom schema use integers. Rejecting floats also
    // prevents precision loss before metadata-policy validation.
    if (!Number.isSafeInteger(value)) return this.fail();
    return value;
  }

  private parseLiteral<T extends null | boolean>(literal: string, value: T): T {
    if (
      this.source.slice(this.index, this.index + literal.length) !== literal
    ) {
      return this.fail();
    }
    this.index += literal.length;
    return value;
  }

  private skipWhitespace(): void {
    while (/\s/.test(this.source[this.index] ?? "")) this.index += 1;
  }

  private fail(): never {
    throw new UpdateError(this.errorCode);
  }
}

function isDigit(value: string | undefined): boolean {
  return value !== undefined && value >= "0" && value <= "9";
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}
