import { config } from "../config.js";

export function Footer() {
    return (
        <footer className="footer">
            <div className="footer__inner">
                <span>CRISP-QES · v3 · {config.chain.name}</span>
                <span className="row">
                    <a
                        href="https://github.com/0xalik/crisp-qes"
                        target="_blank"
                        rel="noreferrer"
                    >
                        Source
                    </a>
                    <a
                        href={`${config.blockExplorerUrl}/address/${config.petitionRegistryV2}`}
                        target="_blank"
                        rel="noreferrer"
                    >
                        Contracts
                    </a>
                </span>
            </div>
        </footer>
    );
}
