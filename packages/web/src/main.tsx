import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.js";
import { WalletProvider } from "./lib/walletContext.js";
import "./i18n.js";
import "./styles.css";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("missing #root");
createRoot(rootEl).render(
    <React.StrictMode>
        <WalletProvider>
            <App />
        </WalletProvider>
    </React.StrictMode>,
);
