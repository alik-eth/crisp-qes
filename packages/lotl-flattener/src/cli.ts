#!/usr/bin/env node
// crisp-qes-flatten CLI.
//
//   crisp-qes-flatten --in <lotl.xml> --out <manifest.json>
//
// Reads a local LOTL XML, walks each Member State trusted list pointer,
// flattens QES-issuing CAs, and writes a Pedersen-Merkle manifest. Prints
// the bytes32 root to stdout so deploy scripts can pipe it directly:
//
//   ROOT=$(crisp-qes-flatten --in lotl.xml --out manifest.json)

import { Command } from "commander";
import { flattenToFile, TREE_DEPTH } from "./index.js";

const main = async (): Promise<void> => {
  const program = new Command()
    .name("crisp-qes-flatten")
    .description(
      "Flatten an LOTL bundle into a Pedersen-Merkle trust-root manifest for CRISP-QES.",
    )
    .requiredOption("--in <path>", "path to LOTL XML on disk")
    .requiredOption("--out <path>", "path to write manifest.json")
    .option("--filter-country <iso>", "restrict to one ISO country code (e.g. UA)")
    .option(
      "--tree-depth <n>",
      "merkle tree depth (default 16)",
      (v) => Number.parseInt(v, 10),
      TREE_DEPTH,
    )
    .option("--lotl-version <id>", "lotl version label written to manifest", "unknown")
    .option("--built-at <iso>", "override builtAt timestamp (for reproducibility)");

  program.parse();
  const o = program.opts<{
    in: string;
    out: string;
    filterCountry?: string;
    treeDepth: number;
    lotlVersion: string;
    builtAt?: string;
  }>();

  try {
    const result = await flattenToFile({
      in: o.in,
      out: o.out,
      ...(o.filterCountry ? { filterCountry: o.filterCountry } : {}),
      treeDepth: o.treeDepth,
      lotlVersion: o.lotlVersion,
      ...(o.builtAt ? { builtAt: o.builtAt } : {}),
    });
    // Stdout: the bytes32 root (so shell wrappers can capture it).
    process.stdout.write(`${result.manifest.root}\n`);
    // Stderr: human-readable summary.
    process.stderr.write(
      `flattened ${result.caCount} CA(s) at depth ${result.manifest.treeDepth} into ${o.out}\n`,
    );
  } catch (e) {
    process.stderr.write(`${e instanceof Error ? e.stack ?? e.message : String(e)}\n`);
    process.exit(1);
  }
};

main();
