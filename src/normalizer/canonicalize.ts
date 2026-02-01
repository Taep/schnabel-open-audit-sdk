type JsonSafe =
  | null
  | boolean
  | number
  | string
  | JsonSafe[]
  | { [k: string]: JsonSafe };

function toJsonSafe(value: unknown, seen: WeakSet<object>): JsonSafe {
  if (value === null) return null;

  const t = typeof value;

  if (t === "string" || t === "number" || t === "boolean") return value as any;

  if (t === "bigint") return value.toString();
  if (t === "undefined") return null;
  if (t === "function") return "[Function]";
  if (t === "symbol") return value.toString();

  if (Array.isArray(value)) {
    return value.map(v => toJsonSafe(v, seen));
  }

  if (t === "object") {
    const obj = value as Record<string, unknown>;
    if (seen.has(obj as any)) return "[Circular]";
    seen.add(obj as any);

    const out: Record<string, JsonSafe> = {};
    for (const k of Object.keys(obj).sort()) {
      out[k] = toJsonSafe(obj[k], seen);
    }
    return out;
  }

  // fallback
  try {
    return String(value);
  } catch {
    return "[Unstringifiable]";
  }
}

/**
 * Deterministic JSON stringify:
 * - deep key sort
 * - undefined -> null
 * - bigint/function/symbol safe
 * - circular -> "[Circular]"
 */
export function canonicalizeJson(value: unknown): string {
  const safe = toJsonSafe(value, new WeakSet());
  return JSON.stringify(safe);
}
