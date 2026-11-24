// RFC 8785 (JSON Canonicalization Scheme), restricted to the values pqam uses.
//
// pqam profile restriction: numbers must be safe integers. Amounts are decimal strings, and
// times and counts are integers, so floats never appear. For safe integers, ECMAScript number
// serialisation (which JCS adopts) is just the decimal digits, so the restriction removes the
// only part of JCS that implementations get wrong. Object keys are sorted by UTF-16 code units
// (JavaScript's default sort order, the order JCS requires). Strings are serialised the way
// JSON.stringify does it, which is exactly the JCS string encoding.

export class CanonicalizationError extends Error {}

export function canonicalize(value) {
  return ser(value, "$");
}

function ser(v, path) {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "string":
      if (!v.isWellFormed()) throw new CanonicalizationError(`${path}: lone surrogate in string`);
      return JSON.stringify(v);
    case "number":
      if (!Number.isSafeInteger(v)) throw new CanonicalizationError(`${path}: only safe integers are allowed (got ${v}); put amounts in strings`);
      return Object.is(v, -0) ? "0" : String(v);
    case "object": {
      if (Array.isArray(v)) return "[" + v.map((x, i) => ser(x, `${path}[${i}]`)).join(",") + "]";
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) throw new CanonicalizationError(`${path}: only plain objects are allowed`);
      const keys = Object.keys(v).sort();
      return "{" + keys.filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ":" + ser(v[k], `${path}.${k}`)).join(",") + "}";
    }
    default:
      throw new CanonicalizationError(`${path}: ${typeof v} cannot be canonicalised`);
  }
}
