import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
const app = buildApp({ config });

app.listen({ port: config.port, host: "0.0.0.0" })
    .then(() => {
        app.log.info(
            { chainId: config.chainId, registry: config.registry },
            "relayer up",
        );
    })
    .catch((err) => {
        app.log.error(err);
        process.exit(1);
    });
