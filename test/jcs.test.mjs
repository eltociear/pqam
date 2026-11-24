import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize, CanonicalizationError } from "../src/jcs.mjs";

test("keys sorted by UTF-16 code units (RFC 8785 3.2.3 example)", () => {
  const o = { "€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh", "1": "One", "😀": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis" };
  const keys = Object.keys(JSON.parse(canonicalize(o)));
  // JSON.parse puts the integer-like key first; compare the serialised order instead.
  const order = canonicalize(o).match(/"((?:[^"\\]|\\.)*)":/g).map((k) => JSON.parse(k.slice(0, -1)));
  assert.deepEqual(order, ["\r", "1", "\u0080", "ö", "€", "😀", "דּ"]);
  assert.equal(keys.length, 7);
});

test("nesting, arrays, literals, escapes", () => {
  assert.equal(canonicalize({ b: [1, true, null, "x\n\"\u001f"], a: { d: 0, c: -5 } }), '{"a":{"c":-5,"d":0},"b":[1,true,null,"x\\n\\"\\u001f"]}');
});

test("undefined members are dropped (as JSON.stringify does)", () => {
  assert.equal(canonicalize({ a: 1, b: undefined }), '{"a":1}');
});

test("refuses floats, unsafe integers, -0 normalised, lone surrogates, non-plain objects", () => {
  for (const bad of [1.5, 2 ** 53, NaN, Infinity, "\ud800", new Date(0), new Map(), 10n, () => 1])
    assert.throws(() => canonicalize({ x: bad }), CanonicalizationError, String(bad));
  assert.equal(canonicalize(-0), "0");
});
