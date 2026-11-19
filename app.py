"""ContractLens — Gradio demo for the Agent Games Wildcard track.

Paste a contract address (BSC / Ethereum) or paste Solidity source and
get a plain-language explanation of what the contract can do, what its
owner can do, and what to watch out for — before you interact with it.

The deterministic analysis (Sourcify source + ABI, public-RPC bytecode,
proxy slot, owner() call, 12 static risk checks, risk score) runs with
no key at all. The AI narrative is written by a Nous free model and
needs a free Nous API key: paste one in the key box, or set it as the
NOUS_API_KEY secret on the Space. The key is never stored or logged.
Without a key you still get the full deterministic report.

Public API (same function as the UI): Gradio /predict.
"""
import os

import gradio as gr

import agent

SAMPLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "sample_token.sol")
try:
    with open(SAMPLE_PATH, encoding="utf-8") as f:
        SAMPLE_SOURCE = f.read()
except OSError:
    SAMPLE_SOURCE = ""


def predict(address, chain_name, source, api_key):
    """Gradio entrypoint — returns the markdown report. Never logs the key."""
    chain_id = 56 if chain_name == "BSC" else 1
    try:
        result = agent.analyze(
            address=(address or "").strip() or None,
            source=(source or "").strip() or None,
            chain_id=chain_id,
            api_key=(api_key or "").strip() or None,
        )
        return result["report"]
    except ValueError as e:
        return f"# Input error\n\n{e}"
    except Exception as e:  # noqa: BLE001 - show the error, don't crash the UI
        return (
            "# Analysis failed\n\n"
            f"`{e}`\n\n"
            "The public data sources (Sourcify / RPC) may be temporarily "
            "unreachable. Try again in a minute, or paste the source code "
            "directly — pasted source needs no network at all."
        )


DESCRIPTION = """\
## ContractLens — understand a contract before you touch it

Paste a **contract address** (BSC or Ethereum) or paste **Solidity source**.
The agent fetches the verified source from Sourcify, reads the bytecode
and the owner from a public RPC, runs 12 static risk checks, and scores
the contract 0–100. With a free Nous API key it also writes a
plain-language explanation.

**No key needed for the deterministic report.** The AI narrative needs a
free Nous key — paste one below or set `NOUS_API_KEY` as a Space secret.
Get a key at [portal.nousresearch.com](https://portal.nousresearch.com)
(free plan). Your key is never stored or logged.

**Honest limits:** a low score never proves a contract is safe or
sellable — it only means these 12 patterns were not found. Unverified
contracts cannot be source-checked at all; paste the source for the
deep check.
"""

demo = gr.Interface(
    fn=predict,
    inputs=[
        gr.Textbox(label="Contract address (0x…, BSC or Ethereum)",
                   placeholder="0x55d398326f99059fF775485246999027B3197955"),
        gr.Dropdown(choices=["BSC", "Ethereum"], value="BSC",
                    label="Chain"),
        gr.Textbox(label="Or paste Solidity source (optional)",
                   lines=8,
                   placeholder="// paste contract source here for the deep check"),
        gr.Textbox(label="Nous API key (optional, for the AI explanation)",
                   type="password",
                   placeholder="sk-… (free plan, portal.nousresearch.com)"),
    ],
    outputs=gr.Markdown(label="Report"),
    title="ContractLens — a Nous-powered contract explainer",
    description=DESCRIPTION,
    examples=[
        ["0x55d398326f99059fF775485246999027B3197955", "BSC", "", ""],
        ["0x9dd4C7D3276609892cF723a90A5AF3f8df40C79A", "BSC", "", ""],
        ["", "BSC", SAMPLE_SOURCE, ""],
    ],
    flagging_mode="never",
)

if __name__ == "__main__":
    demo.launch()
