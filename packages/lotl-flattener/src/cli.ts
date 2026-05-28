#!/usr/bin/env node
// crisp-qes-flatten CLI.
//
//   # LOTL XML (multi-country trust list)
//   crisp-qes-flatten --in <lotl.xml> --out <manifest.json>
//
//   # Diia .p7b cert bundle (single-issuer trust list)
//   crisp-qes-flatten --p7b <bundle.p7b> --out <manifest.json>
//
// Exactly one of `--in` / `--p7b` must be supplied. Both paths emit the same
// Pedersen-Merkle manifest schema (one leaf per kept CA), so the SDK and
// deploy scripts treat the outputs interchangeably. Prints the bytes32
// root to stdout so deploy scripts can pipe it directly:
//
//   ROOT=$(crisp-qes-flatten --p7b diia_ecdsa.p7b --out manifest.json)

import { Command } from "commander";
import { flattenFromP7bToFile, flattenToFile, TREE_DEPTH } from "./index.js";

const main = async (): Promise<void> => {
  const program = new Command()
    .name("crisp-qes-flatten")
    .description(
      "Flatten an LOTL bundle or a .p7b cert bundle into a Pedersen-Merkle " +
        "trust-root manifest for CRISP-QES.",
    )
    .option("--in <path>", "path to LOTL XML on disk")
    .option("--p7b <path>", "path to a CMS-SignedData (.p7b) cert bundle on disk")
    .requiredOption("--out <path>", "path to write manifest.json")
    .option("--filter-country <iso>", "restrict LOTL ingest to one ISO country code (e.g. UA)")
    .option(
      "--tree-depth <n>",
      "merkle tree depth (default 16)",
      (v) => Number.parseInt(v, 10),
      TREE_DEPTH,
    )
    .option("--lotl-version <id>", "lotl/bundle version label written to manifest", "unknown")
    .option("--built-at <iso>", "override builtAt timestamp (for reproducibility)");

  program.parse();
  const o = program.opts<{
    in?: string;
    p7b?: string;
    out: string;
    filterCountry?: string;
    treeDepth: number;
    lotlVersion: string;
    builtAt?: string;
  }>();

  if ((o.in === undefined) === (o.p7b === undefined)) {
    process.stderr.write("crisp-qes-flatten: pass exactly one of --in / --p7b\n");
    process.exit(2);
  }

  try {
    const result = o.p7b
      ? await flattenFromP7bToFile({
          in: o.p7b,
          out: o.out,
          treeDepth: o.treeDepth,
          lotlVersion: o.lotlVersion,
          ...(o.builtAt ? { builtAt: o.builtAt } : {}),
        })
      : await flattenToFile({
          in: o.in!,
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
