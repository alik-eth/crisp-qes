// Shared viem public client for v2 contracts.
import { createPublicClient, http } from "viem";
import { config } from "../config";

export const publicClient = createPublicClient({
    chain: config.chain,
    transport: http(config.rpcUrl),
});
