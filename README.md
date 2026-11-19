# ContractLens — a Nous-powered smart-contract explainer & risk spotter

Paste a BSC/Ethereum contract address (or paste Solidity source) and
ContractLens tells you in plain language what the contract can do,
what its owner can do, and what to watch out for — before you touch it.

Built for the **Agent Games (zkVerify) Wildcard track** by @0x-g0blinz.
Deadline: entries close 21 Nov 2026, 22:00 UTC.

## What it does

- **Deterministic layer (no key needed):** verified source + ABI from
  Sourcify, bytecode / EIP-1967 proxy slot / `owner()` from public RPC,
  function selectors extracted from the bytecode dispatch table and
  resolved via a built-in table + 4byte.directory, and 12 static risk
  checks (owner mint, uncapped fees, sell discrimination, blacklist,
  trading toggle, max-tx/wallet, pause, proxy/delegatecall, owner sweep,
  privileged setters, live ownership, custom accounting) with
  file/line/function evidence, plus a 0–100 risk score. A low score
  never proves a contract safe or sellable.
- **AI layer (free Nous key):** the facts go to a Nous free model
  (`qwen/qwen4-max:free` → `longcat-2.5:free` → `hy4-flash:free`) via
  the public OpenAI-compatible inference API, with a grounding system
  prompt ("cannot tell from the data" when unsupported; no safety
  guarantees, no financial advice). The key comes from the user (UI box
  or `NOUS_API_KEY` env/Space secret), is never stored or logged, and
  the POST refuses redirects so the key cannot leak. Without a key the
  full deterministic report still works.

## Run it

```bash
pip install -r requirements.txt
python app.py        # Gradio UI on http://127.0.0.1:7860
python3 -m unittest test_agent   # 16/16 tests
```

Or call the agent directly:

```python
from agent import analyze
print(analyze("0x55d398326f99059fF775485246999027B3197955", "BSC"))
```

## Verified live (19 Nov 2026)

| Contract | Result |
|---|---|
| USDT on BSC `0x55d3…7955` | Verified, 20 functions, owner mint + live ownership flagged → **55 HIGH** |
| BSCCAT `0x9dd4…C79A` | Unverified, 76 bytecode selectors, functions read from bytecode → **20 MEDIUM** |
| Pasted honeypot sample (`sample_token.sol`) | **100 CRITICAL**, evidence with file:line and enclosing function |

## Limits (honest)

A low score never proves a contract is safe or sellable; unverified
contracts cannot be source-checked; the static checks are regex-based,
not a full audit; the AI narrative needs a free Nous key; free-tier CPU
can take a few seconds per analysis.

## Files

- `agent.py` — the agent core (Sourcify/RPC/4byte fetchers, selector
  extraction, 12 static checks, risk score, Nous client, `render_report()`)
- `app.py` — Gradio UI (address/chain/source/key inputs, 3 examples)
- `test_agent.py` — 16 tests, including a live Nous test and mocked
  end-to-end analyses
- `sample_token.sol` — deliberate honeypot fixture
- `requirements.txt` — `gradio==5.50.0`, `requests==2.32.3`

## License

MIT
