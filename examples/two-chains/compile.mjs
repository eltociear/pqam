// Compiles StandIns.sol into artifacts/StandIns.json (solc 0.8.30, cancun, optimizer 200).
import solc from "solc";
import { readFileSync, writeFileSync } from "node:fs";
const src = readFileSync(new URL("StandIns.sol", import.meta.url), "utf8");
const out = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources: { "StandIns.sol": { content: src } },
  settings: { evmVersion: "cancun", optimizer: { enabled: true, runs: 200 }, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } } })));
const errs = (out.errors ?? []).filter((e) => e.severity === "error");
if (errs.length) { console.error(errs.map((e) => e.formattedMessage).join("\n")); process.exit(1); }
const r = {};
for (const [n, c] of Object.entries(out.contracts["StandIns.sol"])) r[n] = { abi: c.abi, bytecode: "0x" + c.evm.bytecode.object, deployedBytecode: "0x" + c.evm.deployedBytecode.object };
writeFileSync(new URL("artifacts/StandIns.json", import.meta.url), JSON.stringify(r, null, 1) + "\n");
console.log("compiled", Object.keys(r).join(", "));
