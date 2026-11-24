import "@fontsource/im-fell-english-sc/400.css";
import "@fontsource-variable/inter/index.css";
import "@fontsource-variable/jetbrains-mono/index.css";
import "./styles.css";

import { QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { makeQueryClient } from "./api/hooks";
import { App } from "./App";

const root = document.getElementById("root");
if (!root) throw new Error("index.html has no #root element");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={makeQueryClient()}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
