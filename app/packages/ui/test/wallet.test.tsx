import { describe, it, expect, beforeAll, afterEach } from "vitest";
import React from "react";
import { render, screen, fireEvent, waitFor, within, cleanup } from "@testing-library/react";
import { SimulationAdapter } from "@zknox/pq-core";
import { Wallet } from "../src";

beforeAll(() => {
  // jsdom lacks these
  (globalThis as any).requestAnimationFrame = (cb: FrameRequestCallback) => setTimeout(() => cb(performance.now()), 0) as unknown as number;
  (globalThis as any).cancelAnimationFrame = (id: number) => clearTimeout(id);
});

// Testing Library only registers its own cleanup when vitest runs with `globals`, which this config does
// not. Without it the balance tween keeps a timer alive past the teardown and setState throws into a torn
// down jsdom, which fails the run even though both tests pass.
afterEach(cleanup);

const dialog = () => screen.getByRole("dialog");
const clickIn = (container: HTMLElement, name: string) => fireEvent.click(within(container).getByRole("button", { name }));

describe("Wallet over the simulation adapter", () => {
  it("creates the vault, links, protects, spends as the public account", async () => {
    const sim = new SimulationAdapter({ chainId: 11155111, eth: 2500000000000000000n });
    render(<Wallet networks={[{ id: "sim", name: "Sepolia", chainId: 11155111, kind: "simulation", adapter: sim }]} />);
    await screen.findByText("No vault on Sepolia");

    // create the vault
    fireEvent.click(screen.getByRole("button", { name: "Create vault" }));
    clickIn(dialog(), "Create");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), { timeout: 5000 });
    await screen.findByText(/Created the ML-DSA-44 vault/);

    // link the public account
    fireEvent.click(screen.getByRole("button", { name: "Link to vault" }));
    clickIn(dialog(), "Link");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), { timeout: 5000 });
    await screen.findByText(/Linked to the vault/);

    // protect everything above the reserve (sweep)
    fireEvent.click(screen.getAllByRole("button", { name: "Protect funds" })[0]);
    clickIn(dialog(), "Protect");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), { timeout: 5000 });
    await screen.findByText(/Swept the public account into the vault/);
    const s = await sim.read();
    expect(s.eoa.eth).toBe(50000000000000000n);
    expect(s.vault!.eth).toBe(2450000000000000000n);

    // the vault sends as the public account
    fireEvent.click(screen.getByRole("button", { name: "Send as public" }));
    const d = dialog();
    fireEvent.change(within(d).getByPlaceholderText("0x…"), { target: { value: "0x" + "11".repeat(20) } });
    clickIn(d, "Send");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull(), { timeout: 8000 });
    await screen.findByText(/as the public account/);
    expect((await sim.read()).vault!.eth).toBe(2450000000000000000n - 250000000000000000n);
  });

  it("shows an error from the adapter inside the dialog", async () => {
    const sim = new SimulationAdapter({ chainId: 1, eth: 100000000000000000n });
    render(<Wallet networks={[{ id: "sim", name: "Ethereum", chainId: 1, kind: "simulation", adapter: sim }]} />);
    await screen.findByText("No vault on Ethereum");
    fireEvent.click(screen.getAllByRole("button", { name: "Send" })[0]);
    const d = dialog();
    fireEvent.change(within(d).getByPlaceholderText("0x…"), { target: { value: "0x" + "22".repeat(20) } });
    fireEvent.change(within(d).getByDisplayValue("0.25"), { target: { value: "5" } });
    clickIn(d, "Send");
    await screen.findByText("Not enough ETH in the public account", {}, { timeout: 5000 });
  });
});
