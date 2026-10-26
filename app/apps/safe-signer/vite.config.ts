import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `manifest.json` in public/ makes this servable as a Safe App too: app.safe.global loads it in an iframe
// from whatever URL it is served at. It works the same standalone, which is how the relayer step is run.
// BASE is the path the built site is served from. Safe{Wallet} fetches `<the URL you paste>/manifest.json`,
// so on GitHub Pages under https://<org>.github.io/<repo>/ the build needs BASE=/<repo>/ or every asset
// resolves against the domain root and the page loads blank inside the frame.
export default defineConfig({
  base: process.env.BASE ?? "/",
  plugins: [react()],
  server: {
    port: 5174,
    fs: { allow: ["../../.."] },
    // the Safe interface loads an app in an iframe and reads its manifest cross-origin
    headers: { "Access-Control-Allow-Origin": "*" },
  },
  preview: { port: 5174, headers: { "Access-Control-Allow-Origin": "*" } },
});
