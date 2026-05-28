import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";

const cfg = loadConfig();

buildApp({ config: cfg })
    .then((app) =>
        app
            .listen({ port: cfg.port, host: "0.0.0.0" })
            .then(() =>
                app.log.info(
                    {
                        port: cfg.port,
                        suite: "ristretto255-SHA512",
                        attesterAddr: (cfg as { attesterKey: string }).attesterKey
                            ? "<<see /healthz>>"
                            : null,
                    },
                    "oprf up",
                ),
            ),
    )
    .catch((err: unknown) => {
        // eslint-disable-next-line no-console
        console.error("[oprf] fatal:", err);
        process.exit(1);
    });
