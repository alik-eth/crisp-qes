import Fastify from "fastify";
import { z } from "zod";

const SubmitBody = z.object({
    petitionId: z.string().regex(/^\d+$/),
    nullifier: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
    proof: z.string().regex(/^0x[0-9a-fA-F]+$/),
    publicInputs: z.array(z.string().regex(/^0x[0-9a-fA-F]{64}$/)).length(4),
});

const app = Fastify({ logger: true });

app.get("/healthz", async () => ({ ok: true }));

app.post("/submit", async (req, reply) => {
    const parsed = SubmitBody.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });
    // TODO: viem wallet client → registry.signPetition(...) → return tx hash.
    return reply.code(501).send({ error: "not implemented" });
});

const port = Number(process.env.PORT ?? 8787);
app.listen({ port, host: "0.0.0.0" }).catch((err) => {
    app.log.error(err);
    process.exit(1);
});
