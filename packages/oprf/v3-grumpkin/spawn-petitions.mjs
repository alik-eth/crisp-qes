// Spawn 5 funny demo petitions on PetitionRegistryV2 (Sepolia).
// Run from this dir (viem resolves here). Key stays out of any agent context:
//   ! PRIVATE_KEY=0x<funded-sepolia-key> node spawn-petitions.mjs
//
// Each createPetition locks the 0.001 ETH CREATION_DEPOSIT (refundable after
// the deadline). 5 petitions => 0.005 ETH + gas. Deployer 0xB8d121CD… is funded.

import { readFileSync } from "node:fs";
import { createWalletClient, createPublicClient, http, stringToHex } from "viem";
import { baseSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

// Load ./.env (gitignored) into process.env if not already set. Tiny parser —
// no dotenv dependency. Lines: KEY=VALUE, '#' comments and blanks ignored.
try {
    for (const line of readFileSync(new URL("./.env", import.meta.url), "utf8").split("\n")) {
        const t = line.trim();
        if (!t || t.startsWith("#")) continue;
        const eq = t.indexOf("=");
        if (eq < 0) continue;
        const k = t.slice(0, eq).trim();
        const v = t.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
        if (!(k in process.env)) process.env[k] = v;
    }
} catch { /* no .env — fall back to process.env */ }

const RPC = process.env.RPC_URL ?? "https://base-sepolia-rpc.publicnode.com";
const REGISTRY = "0x6b0C722fa50F6325028781DC5A25e9beC1fE4a89"; // PetitionRegistryV2
const DEPOSIT = 1000000000000000n; // CREATION_DEPOSIT = 0.001 ETH
const THRESHOLD = 100;
const DEADLINE = BigInt(Math.floor(Date.now() / 1000) + 30 * 86400); // +30 days

const ABI = [
    {
        type: "function",
        name: "createPetition",
        stateMutability: "payable",
        inputs: [
            { name: "fullText", type: "bytes" },
            { name: "deadline", type: "uint64" },
            { name: "threshold", type: "uint32" },
        ],
        outputs: [{ name: "id", type: "uint256" }],
    },
];

// title\n\nbody  (first line = title, ≤200 chars — matches the web convention)
const PETITIONS = [
    {
        title: "Визнати сало стратегічним національним резервом",
        body: "Пропонуємо офіційно внести сало до переліку стратегічних запасів держави. Кожна родина — міні-резерв. Безпеку гарантовано, настрій підвищено.",
    },
    {
        title: "Скасувати понеділки (принаймні ранкові)",
        body: "Понеділок до обіду оголосити необов'язковим. Робочий тиждень починати з «легкого вівторка». Продуктивність зросте, кава подешевшає від попиту.",
    },
    {
        title: "Зобов'язати котів сплачувати податок муркотінням",
        body: "Кожен кіт, що мешкає в теплі та ситості, має відраховувати державі добову норму муркотіння. Несплата карається ігноруванням (як завжди).",
    },
    {
        title: "Запровадити свято «День відпочинку після свят»",
        body: "Після кожного свята оголошувати додатковий вихідний для відновлення сил. Бо святкувати — теж робота, і вона виснажує.",
    },
    {
        title: "Заборонити спойлери серіалів у громадському транспорті",
        body: "Розкриття сюжету вголос у маршрутці прирівняти до дрібного хуліганства. Міра покарання — переказати кінцівку без жодних емоцій.",
    },
];

const pk = process.env.ADMIN_PRIVATE_KEY ?? process.env.PRIVATE_KEY;
if (!pk) {
    console.error("Set ADMIN_PRIVATE_KEY in .env (0x-prefixed, funded Sepolia EOA). Aborting.");
    process.exit(1);
}
const account = privateKeyToAccount(pk);
const publicClient = createPublicClient({ chain: baseSepolia, transport: http(RPC) });
const wallet = createWalletClient({ account, chain: baseSepolia, transport: http(RPC) });

console.log("creator:", account.address);
const bal = await publicClient.getBalance({ address: account.address });
console.log("balance:", (Number(bal) / 1e18).toFixed(5), "ETH");
console.log(`creating ${PETITIONS.length} petitions (deposit ${Number(DEPOSIT) / 1e18} ETH each)…\n`);

for (const [i, p] of PETITIONS.entries()) {
    const fullText = `${p.title}\n\n${p.body}`;
    const hash = await wallet.writeContract({
        address: REGISTRY,
        abi: ABI,
        functionName: "createPetition",
        args: [stringToHex(fullText), DEADLINE, THRESHOLD],
        value: DEPOSIT,
    });
    process.stdout.write(`#${i + 1} ${p.title}\n  tx ${hash} … `);
    const rcpt = await publicClient.waitForTransactionReceipt({ hash });
    console.log(rcpt.status === "success" ? "OK ✓" : "FAILED ✗");
}
console.log("\nDone. Refresh /petitions on crisp-qes-web.fly.dev.");
