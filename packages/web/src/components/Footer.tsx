export function Footer() {
    return (
        <footer className="footer">
            <div className="footer__inner">
                <span>
                    CRISP-QES · v2 · Sepolia
                </span>
                <span className="row">
                    <a
                        href="https://github.com/0xalik/crisp-qes"
                        target="_blank"
                        rel="noreferrer"
                    >
                        Source
                    </a>
                    <a
                        href="https://sepolia.etherscan.io/address/0xfB3495aBF58813e1B8638e08665b6b77B42f66F0"
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
