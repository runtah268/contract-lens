"""ContractLens — a Nous-powered smart-contract explainer & risk spotter.

Paste a contract address (BSC / Ethereum) or paste Solidity source, and
the agent tells you in plain language what the contract can do, what its
owner can do, and what to watch out for — before you interact with it.

How it works (two layers, both honest about their limits):
1. Deterministic layer (no key needed, runs on public data only):
   - Sourcify (public, no key) for verified source + ABI.
   - Public RPC (no key) for bytecode, the EIP-1967 proxy slot, and an
     eth_call to owner() when the contract has one.
   - Bytecode function selectors, resolved against a built-in table and
     the public 4byte.directory (no key).
   - 12 static risk checks on the source (minting, fee setters, sell
     discrimination, blacklist, trading toggle, max-tx/wallet, pause,
     proxy/delegatecall, owner sweep, privileged setters, live ownership,
     custom accounting). A bare keyword is never the finding — what
     matters is who can call it (onlyOwner) and whether a cap exists.
   - A deterministic 0-100 risk score from the findings. A clean static
     pass NEVER proves a contract is safe or sellable; it only says
     these 12 patterns were not found.
2. Nous layer (needs a free Nous API key, supplied by the user):
   - The deterministic facts + a source excerpt are sent to a Nous free
   model (qwen4-max first, then longcat-2.5, then hy4-flash), which
   writes the plain-language explanation. The model is instructed to
   ground every claim in the supplied facts and to say when it cannot
   tell. No key is ever stored or logged; without a key the agent still
   returns the full deterministic report and says how to get a free key.

No credential is hardcoded anywhere. The Nous endpoint is the public
OpenAI-compatible inference API; the base URL can be overridden with
NOUS_BASE_URL (tests point it at the local Hermes proxy).
"""
import json
import os
import re
import urllib.error
import urllib.request

# ---------------------------------------------------------------- config

NOUS_API_URL = os.environ.get(
    "NOUS_API_URL", "https://inference-api.nousresearch.com/v1"
)
NOUS_MODELS = [
    "qwen/qwen4-max:free",
    "meituan/longcat-2.5:free",
    "tencent/hy4-flash:free",
]
NOUS_TIMEOUT = 90  # seconds per model attempt

CHAINS = {
    56: {
        "name": "BSC",
        "rpcs": [
            "https://bsc.blockrazor.xyz",
            "https://bsc-dataseed.bnbchain.org",
            "https://bsc-rpc.publicnode.com",
        ],
    },
    1: {
        "name": "Ethereum",
        "rpcs": [
            "https://eth.llamarpc.com",
            "https://cloudflare-eth.com",
            "https://ethereum-rpc.publicnode.com",
        ],
    },
}

SOURCIFY = "https://sourcify.dev/server/v2/contract"
FOURBYTE = "https://www.4byte.directory/api/v1/signatures/"
EIP1967_IMPL_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
ZERO_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}

# Common function selectors (4-byte) -> human name. Used before 4byte.
KNOWN_SELECTORS = {
    "0x06fdde03": "name()",
    "0x95d89b41": "symbol()",
    "0x313ce567": "decimals()",
    "0x70a08231": "balanceOf(address)",
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0xdd62ed3e": "allowance(address,address)",
    "0x18160ddd": "totalSupply()",
    "0x40c10f19": "mint(address,uint256)",
    "0x42966c68": "burn(uint256)",
    "0x79cc6790": "burn(address,uint256)",
    "0x8da5cb5b": "owner()",
    "0x715018a6": "renounceOwnership()",
    "0xf2fde38b": "transferOwnership(address)",
    "0x8456cb59": "pause()",
    "0x3f4ba83a": "unpause()",
    "0x5c975abb": "paused()",
    "0xa22cb465": "setApprovalForAll(address,bool)",
    "0xd505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "0xac9650d8": "multicall(bytes[])",
    "0x7ff36ab5": "swapExactETHForTokens(uint256,address[],address,uint256)",
    "0x18cbafe5": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
    "0x38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "0xfb3bdb41": "swapETHForExactTokens(uint256,address[],address,uint256)",
    "0xe8e33700": "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
    "0x02751cec": "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
    "0xbaa2abde": "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
    "0xad5c4648": "WETH()",
    "0xd06ca61f": "getAmountsOut(uint256,address[])",
    "0x0902f1ac": "getReserves()",
    "0x6a627842": "mint(address)",
}

# ---------------------------------------------------------------- http

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _http_get(url, timeout=20):
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", _BROWSER_UA)
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: urllib would otherwise re-send the Authorization
    header to the redirect target, leaking the user's API key."""

    def redirect_request(self, *args):
        raise RuntimeError("redirect refused, verify the endpoint")


def _http_post_json(url, payload, timeout=20, headers=None):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", _BROWSER_UA)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _rpc_call(rpc_url, method, params, timeout=20):
    return _http_post_json(
        rpc_url,
        {"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
        timeout=timeout,
    )


def _rpc_first(chain_id, method, params):
    """Try each public RPC in order; return the first usable result."""
    last_err = None
    for rpc in CHAINS[chain_id]["rpcs"]:
        try:
            data = _rpc_call(rpc, method, params)
            if "result" in data and data["result"] is not None:
                return data["result"], rpc
            if data.get("error"):
                last_err = data["error"]
        except Exception as e:  # noqa: BLE001 - try the next RPC
            last_err = e
    raise RuntimeError(f"all {CHAINS[chain_id]['name']} RPCs failed: {last_err}")


# ---------------------------------------------------------------- chain data

def is_address(value):
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", (value or "").strip()))


def fetch_sourcify(chain_id, address):
    """Return (verified, abi, sources) — sources is {filename: content}."""
    url = f"{SOURCIFY}/{chain_id}/{address}?fields=abi,sources"
    try:
        data = _http_get(url, timeout=25)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, [], {}
        raise
    if not data.get("match"):
        return False, [], {}
    abi = data.get("abi") or []
    sources = {}
    for name, entry in (data.get("sources") or {}).items():
        content = entry.get("content") if isinstance(entry, dict) else None
        if content:
            sources[name] = content
    return True, abi, sources


def fetch_bytecode(chain_id, address):
    code, _rpc = _rpc_first(chain_id, "eth_getCode", [address, "latest"])
    return code or "0x"


def fetch_proxy_implementation(chain_id, address):
    try:
        value, _rpc = _rpc_first(
            chain_id, "eth_getStorageAt", [address, EIP1967_IMPL_SLOT, "latest"]
        )
        if not re.fullmatch(r"0x[0-9a-fA-F]{64}", value or ""):
            return None
        if int(value, 16) == 0:
            return None
    except Exception:  # noqa: BLE001 - proxy check is best-effort
        return None
    return "0x" + value[-40:]


def fetch_owner(chain_id, address):
    """eth_call owner() -> address string, None if no owner() or call fails."""
    data = "0x8da5cb5b" + "0" * 64
    try:
        result, _rpc = _rpc_first(
            chain_id, "eth_call",
            [{"to": address, "data": data}, "latest"],
        )
    except Exception:  # noqa: BLE001 - owner() is best-effort
        return None
    if not result or len(result) < 66:
        return None
    owner = "0x" + result[-40:]
    return owner  # even 0x0: the caller flags it as renounced


def extract_selectors(bytecode):
    """4-byte function selectors from the dispatch table (PUSH4 opcodes)."""
    if not bytecode or bytecode in ("0x", "0X"):
        return []
    hexcode = bytecode[2:] if bytecode.startswith("0x") else bytecode
    # Dispatch table lives at the start; scanning the first 10KB keeps
    # embedded constants (metadata, strings) out of the results.
    found = re.findall(r"63([0-9a-fA-F]{8})", hexcode[:20000])
    seen = []
    for sel in found:
        s = "0x" + sel.lower()
        if s not in seen:
            seen.append(s)
    return seen


def resolve_selector(selector):
    """Human name for a selector: built-in table first, then 4byte.directory."""
    if selector in KNOWN_SELECTORS:
        return KNOWN_SELECTORS[selector], "builtin"
    try:
        data = _http_get(
            f"{FOURBYTE}?hex_signature={selector}", timeout=15
        )
        for entry in data.get("results", [])[:10]:
            sig = entry.get("text_signature", "")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\([A-Za-z0-9,\[\]]*\)", sig):
                return sig, "4byte"
    except Exception:  # noqa: BLE001 - selector resolution is best-effort
        pass
    return None, None


def abi_summary(abi):
    """(functions, events, payable functions) from an ABI list."""
    functions, events, payable = [], [], []
    for entry in abi or []:
        if entry.get("type") == "function":
            name = entry.get("name", "?")
            inputs = ",".join(
                i.get("type", "?") for i in entry.get("inputs", [])
            )
            sig = f"{name}({inputs})"
            functions.append(sig)
            if entry.get("stateMutability") == "payable":
                payable.append(sig)
        elif entry.get("type") == "event":
            events.append(entry.get("name", "?"))
    return functions, events, payable


# ---------------------------------------------------------------- static checks

# Each check: (id, title, severity base, patterns, why-it-matters).
# Severity is raised when the pattern sits in an owner-only function
# without a nearby cap, lowered when a cap is present. A bare keyword
# hit is never more than LOW.
CHECKS = [
    ("owner_mint", "Owner can mint new tokens",
     ["function\\s+mint\\s*\\(", "_mint\\s*\\(", "totalSupply\\s*\\+="],
     "Supply can be inflated at will; the owner mints and sells into holders."),
    ("uncapped_fee", "Owner can change fees/taxes without a cap",
     ["set\\w*[Ff]ee\\s*\\(", "_taxFee\\s*=", "_liquidityFee\\s*=",
      "setBuyFee", "setSellFee", "setTax"],
     "Sell tax can be raised toward 100% after you buy — a classic soft honeypot."),
    ("sell_discrimination", "Sells can be treated differently from buys",
     ["automatedMarketMakerPairs\\s*\\[", "isSell\\b",
      "to\\s*==\\s*\\w*[Pp]air"],
     "Buys succeed while sells revert or get taxed differently — the honeypot signature."),
    ("blacklist", "Owner can blacklist / freeze addresses",
     ["blacklist", "blocklist", "isBlocked", "_banned", "setBlacklist"],
     "The owner can freeze your specific address so you can never transfer or sell."),
    ("trading_toggle", "Owner can open / close trading",
     ["tradingOpen", "tradingActive", "enableTrading", "_launched"],
     "Only insiders trade until the owner flips it; it can also be flipped back off."),
    ("max_tx_wallet", "Owner can set max transaction / max wallet",
     ["setMaxTx", "_maxTxAmount\\s*=", "setMaxWallet", "maxWalletAmount\\s*="],
     "Set to a dust amount and every normal sell reverts while the owner stays exempt."),
    ("pause", "Contract can be paused globally",
     ["\\bPausable\\b", "whenNotPaused", "function\\s+pause\\s*\\("],
     "All transfers can be halted indefinitely; funds frozen contract-wide."),
    ("proxy_delegatecall", "Proxy / delegatecall upgradeability",
     ["delegatecall", "upgradeTo\\s*\\(", "_implementation\\s*="],
     "Clean audited logic today can be swapped for a honeypot tomorrow."),
    ("owner_sweep", "Owner can sweep tokens / BNB out of the contract",
     ["rescueToken", "sweep", "withdrawToken", "claimTokens", "withdrawBNB",
      "\\.call\\s*\\{[^}]*value"],
     "The owner can drain LP, treasury, or any token held by the contract."),
    ("privileged_setters", "Owner can repoint pairs, routers, fee wallets",
     ["setPair", "setRouter", "setMarketingWallet", "setDevWallet",
      "setFeeReceiver"],
     "Fees can be redirected to the owner, or the pair repointed so real sells are taxed."),
    ("ownership_live", "Ownership is live (Ownable / onlyOwner present)",
     ["\\bOwnable\\b", "onlyOwner", "transferOwnership"],
     "Every privileged check above stays exploitable while ownership is live."),
    ("custom_accounting", "Custom transfer / balance accounting",
     ["function\\s+_transfer\\s*\\(", "_beforeTokenTransfer", "tOwned",
      "rOwned", "\\bdeliver\\s*\\(", "rebase"],
     "Balances can be rewritten or shrunk; what your wallet shows is not what you can sell."),
]

_OWNER_RE = re.compile(r"onlyOwner|onlyAdmin|onlyMinter|requiresAuth")
_CAP_RE = re.compile(r"require\s*\([^)]*<=\s*\d+|require\s*\([^)]*<\s*\d+|MAX_[A-Z_]+")
_FUNC_RE = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _enclosing_function(lines, line_no):
    """Name of the function enclosing line_no (0-based), or None.

    Walks back to candidate `function` definitions and keeps the first
    one whose brace depth is still open at line_no — a plain "nearest
    preceding definition" misattributes lines after that function closed.
    """
    for i in range(line_no, max(-1, line_no - 200), -1):
        m = _FUNC_RE.search(lines[i])
        if not m:
            continue
        if i == line_no:
            return m.group(1)  # match sits on the definition line itself
        depth = 0
        opened = False
        closed = False
        for line in lines[i:line_no + 1]:
            depth += line.count("{") - line.count("}")
            if depth > 0:
                opened = True
            elif opened and depth <= 0:
                closed = True
                break
        if opened and not closed:
            return m.group(1)
    return None


def static_checks(source, filename=None):
    """Run the 12 checks on Solidity source. Returns a list of findings.

    Finding: {id, title, severity (HIGH/MEDIUM/LOW), evidence, why}.
    evidence is a list of {file, line, snippet, function}.
    """
    lines = source.splitlines()
    findings = []
    for check_id, title, patterns, why in CHECKS:
        evidence = []
        for pattern in patterns:
            rx = re.compile(pattern)
            for i, line in enumerate(lines):
                if rx.search(line):
                    fn = _enclosing_function(lines, i)
                    evidence.append({
                        "file": filename,
                        "line": i + 1,
                        "snippet": line.strip()[:160],
                        "function": fn,
                    })
                    if len(evidence) >= 4:
                        break
            if len(evidence) >= 4:
                break
        if not evidence:
            continue
        # Severity: owner-only + no cap -> HIGH; owner-only + cap -> MEDIUM;
        # bare keyword -> LOW. Look at the evidence window for modifiers.
        window_lines = []
        for e in evidence[:2]:
            window_lines.extend(lines[max(0, e["line"] - 4): e["line"] + 3])
        window = "\n".join(window_lines)
        has_owner = bool(_OWNER_RE.search(window))
        has_cap = bool(_CAP_RE.search(window))
        if has_owner and not has_cap:
            severity = "HIGH"
        elif has_owner:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        findings.append({
            "id": check_id, "title": title, "severity": severity,
            "evidence": evidence, "why": why,
        })
    return findings


def static_checks_files(files):
    """Run the checks on every (filename, source) pair and merge findings.

    Findings are merged by check id (evidence combined, severity kept at
    the highest found) so risk code in an imported file is not missed.
    """
    merged = {}
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for filename, source in files:
        for f in static_checks(source, filename=filename):
            if f["id"] in merged:
                merged[f["id"]]["evidence"].extend(f["evidence"])
                if order[f["severity"]] < order[merged[f["id"]]["severity"]]:
                    merged[f["id"]]["severity"] = f["severity"]
            else:
                merged[f["id"]] = f
    return list(merged.values())


def risk_score(findings, verified, is_proxy, unverified=False):
    """Deterministic 0-100 score from findings. Higher = riskier.

    `unverified` adds 20 only when an address was given but no source
    could be obtained for it — a pasted-source-only run has fully
    readable source, so it is not penalised.
    """
    score = 0
    for f in findings:
        score += {"HIGH": 25, "MEDIUM": 12, "LOW": 5}[f["severity"]]
    if unverified:
        score += 20  # source not verified — nothing above can be confirmed
    if is_proxy:
        score += 15
    score = min(100, score)
    if score >= 70:
        verdict = "CRITICAL"
    elif score >= 45:
        verdict = "HIGH"
    elif score >= 20:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"
    return score, verdict


# ---------------------------------------------------------------- Nous layer

NOUS_SYSTEM_PROMPT = """You are a smart-contract explainer for normal crypto users, not developers.
You are given DETERMINISTIC FACTS about an EVM contract (functions found,
static risk flags with the exact code lines, ownership and proxy status)
plus an excerpt of its verified source code when available.

Write a short, plain-language report in English with these sections:
1. What this contract does (2-4 sentences, no jargon).
2. What the owner can do (bullet list, only from the facts given).
3. Top risks a user should know (bullet list, ranked; quote the evidence
   line for each risk you mention).
4. One-line verdict: SAFE-LOOKING / CAUTION / HIGH-RISK, with one reason.

Rules: ground EVERY claim in the supplied facts or the source excerpt.
If the facts do not support a claim, say "cannot tell from the data".
Never invent token names, fees, or numbers. Never give financial advice
and never say a contract is safe — at most say no red flags were found
in the checks run. If the source was not verified, say so clearly and
treat all source-based claims as unconfirmed. Keep the whole report
under 350 words."""

SOURCE_EXCERPT_CHARS = 12000


def nous_explain(facts, source_excerpt, api_key, base_url=None):
    """Ask a Nous free model to explain the contract. Returns (text, model).

    Tries each free model in order; a 429, empty answer, or error moves
    on to the next. Raises RuntimeError if every model fails.
    """
    base = (base_url or NOUS_API_URL).rstrip("/")
    user_content = (
        "DETERMINISTIC FACTS (do not contradict these):\n"
        + json.dumps(facts, indent=2)[:6000]
        + "\n\nSOURCE EXCERPT (verified source when available, else empty):\n"
        + (source_excerpt or "(no verified source available)")[:SOURCE_EXCERPT_CHARS]
    )
    last_err = None
    for model in NOUS_MODELS:
        try:
            data = _http_post_json(
                f"{base}/chat/completions",
                {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": NOUS_SYSTEM_PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                    "max_tokens": 2000,
                    "temperature": 0,
                },
                timeout=NOUS_TIMEOUT,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            if data.get("error"):
                last_err = f"{model}: {data['error']}"
                continue
            choices = data.get("choices") or [{}]
            content = (choices[0].get("message") or {}).get("content")
            if content and content.strip():
                return content.strip(), model
            last_err = f"{model} returned an empty answer"
        except Exception as e:  # noqa: BLE001 - try the next model
            last_err = f"{model}: {e}"
    raise RuntimeError(f"all Nous models failed: {last_err}")


# ---------------------------------------------------------------- analyze

def analyze(address=None, source=None, chain_id=56, api_key=None,
            base_url=None):
    """Analyze a contract address and/or pasted source.

    Returns a dict with: chain, address, verified, abi/functions,
    bytecode info, selectors, proxy, owner, findings, score, verdict,
    nous (text + model) or nous_error, and a markdown report.
    """
    chain_id = chain_id if chain_id in CHAINS else 56
    chain = CHAINS[chain_id]
    result = {
        "chain": chain["name"], "chain_id": chain_id,
        "address": (address or "").strip() or None,
        "verified": False, "source_available": False,
        "source_origin": None, "abi": [], "functions": [],
        "events": [], "payable_functions": [],
        "bytecode_size": None, "selectors": [], "is_proxy": False,
        "proxy_implementation": None, "owner": None, "owner_renounced": False,
        "findings": [], "score": None, "verdict": None,
        "nous_text": None, "nous_model": None, "nous_error": None,
        "notes": [],
    }
    pasted = (source or "").strip()
    addr = result["address"]

    if addr and not is_address(addr):
        raise ValueError(f"not a valid contract address: {addr}")
    if not addr and not pasted:
        raise ValueError("give a contract address, paste source code, or both")

    combined_source = ""
    source_files = []  # [(filename, content)] — every file gets checked
    if addr:
        code = fetch_bytecode(chain_id, addr)
        if code in ("0x", "0X", ""):
            result["notes"].append(
                "No bytecode at this address on "
                f"{chain['name']} — it may be an externally owned account, "
                "an address on another chain, or a wrong address."
            )
            if not pasted:
                result["score"], result["verdict"] = 0, "UNKNOWN"
                result["report"] = render_report(result)
                return result
            # else fall through: the pasted source is still analyzed below
        result["bytecode_size"] = (len(code) - 2) // 2 if code not in ("0x", "0X", "") else 0
        sels = extract_selectors(code)
        resolved = []
        for sel in sels[:40]:  # cap 4byte lookups
            name, origin = resolve_selector(sel)
            resolved.append({"selector": sel, "name": name, "origin": origin})
        result["selectors"] = resolved
        impl = fetch_proxy_implementation(chain_id, addr)
        if impl:
            result["is_proxy"] = True
            result["proxy_implementation"] = impl
        owner = fetch_owner(chain_id, addr)
        if owner:
            result["owner"] = owner
            result["owner_renounced"] = owner.lower() in ZERO_ADDRESSES
        try:
            verified, abi, sources = fetch_sourcify(chain_id, addr)
        except Exception as e:  # noqa: BLE001 - Sourcify is best-effort
            result["notes"].append(
                f"Sourcify lookup failed ({e}); treating the source as "
                "unverified."
            )
            verified, abi, sources = False, [], {}
        result["verified"] = verified
        result["abi"] = abi
        fns, evs, pay = abi_summary(abi)
        result["functions"], result["events"] = fns, evs
        result["payable_functions"] = pay
        if sources:
            source_files = sorted(
                sources.items(), key=lambda kv: -len(kv[1])
            )
            result["source_available"] = True
            result["source_origin"] = (
                f"Sourcify ({len(sources)} file(s), largest first)"
            )
        elif verified:
            result["notes"].append(
                "Verified on Sourcify but no source file was returned; "
                "static source checks were skipped."
            )
        else:
            result["notes"].append(
                "Source NOT verified on Sourcify — static source checks "
                "cannot run on the deployed code. Paste the source below "
                "for the deep check, or treat the contract as unverified."
            )
    if pasted:
        source_files = [("(pasted by user)", pasted)]
        result["source_available"] = True
        result["source_origin"] = "pasted by user (unverified against the address)"
        if addr and result["verified"]:
            result["notes"].append(
                "Pasted source overrides the Sourcify source for the "
                "static checks; it was NOT verified against the address."
            )

    if source_files:
        result["findings"] = static_checks_files(source_files)
        # The Nous excerpt uses the largest file (usually the token).
        combined_source = source_files[0][1]
    score, verdict = risk_score(
        result["findings"], result["verified"], result["is_proxy"],
        unverified=bool(addr) and not result["source_available"],
    )
    result["score"], result["verdict"] = score, verdict

    key = (api_key or "").strip() or os.environ.get("NOUS_API_KEY", "").strip()
    if key:
        facts = {
            "chain": result["chain"], "address": result["address"],
            "verified_on_sourcify": result["verified"],
            "bytecode_bytes": result["bytecode_size"],
            "is_proxy": result["is_proxy"],
            "proxy_implementation": result["proxy_implementation"],
            "owner": result["owner"],
            "owner_renounced": result["owner_renounced"],
            "functions": result["functions"][:60],
            "payable_functions": result["payable_functions"],
            "bytecode_selectors_named": [
                s["name"] for s in result["selectors"] if s["name"]
            ][:40],
            "bytecode_selectors_unresolved": len(
                [s for s in result["selectors"] if not s["name"]]
            ),
            "risk_score": result["score"], "risk_verdict": result["verdict"],
            "static_findings": [
                {"check": f["title"], "severity": f["severity"],
                 "evidence": [e["snippet"] for e in f["evidence"][:2]],
                 "why": f["why"]}
                for f in result["findings"]
            ],
        }
        try:
            text, model = nous_explain(
                facts, combined_source, key, base_url=base_url
            )
            result["nous_text"], result["nous_model"] = text, model
        except Exception as e:  # noqa: BLE001 - Nous is optional
            result["nous_error"] = str(e)
    else:
        result["notes"].append(
            "No Nous API key supplied, so there is no AI narrative — the "
            "report below is the deterministic analysis only. Add a free "
            "Nous key (portal.nousresearch.com, free plan) in the key box "
            "or as NOUS_API_KEY to get the plain-language explanation."
        )
    result["report"] = render_report(result)
    return result


def render_report(r):
    """Markdown report for the Gradio UI."""
    lines = [f"# ContractLens report — {r['chain']}"]
    if r["address"]:
        lines.append(f"**Address:** `{r['address']}`")
    lines.append(
        f"**Verified on Sourcify:** {'yes' if r['verified'] else 'NO — source unverified'}"
    )
    if r["bytecode_size"] is not None:
        lines.append(f"**Bytecode:** {r['bytecode_size']:,} bytes")
    if r["is_proxy"]:
        lines.append(
            "**Proxy contract:** YES — logic lives at "
            f"`{r['proxy_implementation']}` and can be swapped."
        )
    if r["owner"]:
        status = "RENOWNED (sent to dead/zero address)" if r["owner_renounced"] \
            else "LIVE"
        lines.append(f"**Owner:** `{r['owner']}` ({status})")
    elif r["address"]:
        lines.append("**Owner:** no owner() function found (or call failed)")
    if r["verdict"]:
        lines.append(
            f"\n## Verdict: {r['verdict']}  (deterministic risk score {r['score']}/100)"
        )
        lines.append(
            "_Score comes from the static checks only. A low score never "
            "proves a contract is safe or sellable._"
        )
    if r["findings"]:
        lines.append("\n## Static findings (source checks)")
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for f in sorted(r["findings"], key=lambda x: order[x["severity"]]):
            lines.append(f"\n### [{f['severity']}] {f['title']}")
            lines.append(f"{f['why']}")
            for e in f["evidence"][:3]:
                fn = f" in `{e['function']}()`" if e["function"] else ""
                where = f"{e['file']}:" if e.get("file") else ""
                lines.append(f"- {where}line {e['line']}{fn}: `{e['snippet']}`")
    else:
        lines.append(
            "\n## Static findings\nNo risk patterns found in the checks run "
            "(or no source was available to check)."
        )
    if r["functions"]:
        lines.append(
            f"\n## Functions ({len(r['functions'])} in ABI)"
        )
        lines.append(", ".join(f"`{fn}`" for fn in r["functions"][:40]))
        if len(r["functions"]) > 40:
            lines.append(f"\n_…and {len(r['functions']) - 40} more._")
    if r["selectors"]:
        named = [s for s in r["selectors"] if s["name"]]
        unknown = [s for s in r["selectors"] if not s["name"]]
        lines.append(
            f"\n## Bytecode selectors ({len(r['selectors'])} found)"
        )
        if named:
            lines.append(
                "Recognised: "
                + ", ".join(f"`{s['name']}`" for s in named[:30])
            )
        if unknown:
            lines.append(
                "Unresolved selectors: "
                + ", ".join(s["selector"] for s in unknown[:15])
            )
    if r["nous_text"]:
        lines.append(f"\n## AI explanation (Nous, {r['nous_model']})")
        lines.append(r["nous_text"])
    elif r["nous_error"]:
        lines.append("\n## AI explanation")
        lines.append(f"Nous call failed: `{r['nous_error']}` — showing the "
                    "deterministic report only.")
    if r["notes"]:
        lines.append("\n## Notes")
        for n in r["notes"]:
            lines.append(f"- {n}")
    return "\n".join(lines)
