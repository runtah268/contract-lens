"""Tests for ContractLens (agent.py).

Unit tests use only local fixtures (no network). One live test hits the
local Hermes Nous proxy (127.0.0.1:8645) with a free model to prove the
runtime model path works end to end; it is skipped when the proxy is down.

Run: python3 -m unittest test_agent -v
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import agent

FIXTURES = os.path.dirname(os.path.abspath(__file__))

CLEAN_ERC20 = """
pragma solidity ^0.8.0;
contract CleanToken {
    string public name = "Clean";
    string public symbol = "CLN";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 10 ** 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    constructor() { balanceOf[msg.sender] = totalSupply; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    function approve(address s, uint256 a) external returns (bool) {
        allowance[msg.sender][s] = a;
        return true;
    }
}
"""


def load_sample():
    with open(os.path.join(FIXTURES, "sample_token.sol"), encoding="utf-8") as f:
        return f.read()


class TestStaticChecks(unittest.TestCase):
    def test_honeypot_sample_flags(self):
        findings = {f["id"]: f for f in agent.static_checks(load_sample())}
        for want in ("owner_mint", "uncapped_fee", "blacklist",
                     "trading_toggle", "max_tx_wallet", "pause",
                     "owner_sweep", "ownership_live"):
            self.assertIn(want, findings, f"missing check {want}")
        # Owner-only mint without a cap is the top finding.
        self.assertEqual(findings["owner_mint"]["severity"], "HIGH")
        self.assertEqual(findings["blacklist"]["severity"], "HIGH")
        # Evidence carries line numbers and the enclosing function.
        ev = findings["owner_mint"]["evidence"][0]
        self.assertEqual(ev["function"], "mint")
        self.assertGreater(ev["line"], 0)

    def test_clean_token_no_high(self):
        findings = agent.static_checks(CLEAN_ERC20)
        highs = [f for f in findings if f["severity"] == "HIGH"]
        self.assertEqual(highs, [])
        ids = {f["id"] for f in findings}
        self.assertNotIn("owner_mint", ids)
        self.assertNotIn("blacklist", ids)

    def test_sell_discrimination_pattern(self):
        src = CLEAN_ERC20 + "\n    function isSell(address to) external view returns (bool) { return automatedMarketMakerPairs[to]; }\n"
        findings = {f["id"]: f for f in agent.static_checks(src)}
        self.assertIn("sell_discrimination", findings)


class TestRiskScore(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(agent.risk_score([], True, False), (0, "LOW"))
        highs = [{"severity": "HIGH"}]
        score, verdict = agent.risk_score(highs, True, False)
        self.assertEqual((score, verdict), (25, "MEDIUM"))
        score, verdict = agent.risk_score(highs * 3, True, False)
        self.assertEqual((score, verdict), (75, "CRITICAL"))
        # The +20 unverified penalty applies only when an address was
        # given but no source could be obtained — not to pasted source.
        self.assertEqual(agent.risk_score([], False, False), (0, "LOW"))
        self.assertEqual(
            agent.risk_score([], False, False, unverified=True), (20, "MEDIUM")
        )
        self.assertEqual(agent.risk_score([], True, True), (15, "LOW"))


class TestSelectors(unittest.TestCase):
    def test_extract_push4(self):
        # Minimal dispatch table: PUSH4 transfer, PUSH4 owner, then junk.
        code = "0x6080604052600436106100" + "63a9059cbb146100" + "638da5cb5b146100" + "63deadbeef"
        sels = agent.extract_selectors(code)
        self.assertIn("0xa9059cbb", sels)
        self.assertIn("0x8da5cb5b", sels)

    def test_resolve_builtin(self):
        name, origin = agent.resolve_selector("0xa9059cbb")
        self.assertEqual(name, "transfer(address,uint256)")
        self.assertEqual(origin, "builtin")

    def test_address_validation(self):
        self.assertTrue(agent.is_address("0x9dd4C7D3276609892cF723a90A5AF3f8df40C79A"))
        self.assertFalse(agent.is_address("0x1234"))
        self.assertFalse(agent.is_address("not an address"))


class TestAnalyzeMocked(unittest.TestCase):
    def test_analyze_pasted_source_only(self):
        result = agent.analyze(source=load_sample())
        self.assertIsNone(result["address"])
        self.assertTrue(result["source_available"])
        self.assertEqual(result["source_origin"],
                         "pasted by user (unverified against the address)")
        ids = {f["id"] for f in result["findings"]}
        self.assertIn("owner_mint", ids)
        self.assertGreaterEqual(result["score"], 45)
        self.assertIn(result["verdict"], ("HIGH", "CRITICAL"))
        self.assertIn("Verdict", result["report"])
        self.assertIn("mint", result["report"])

    def test_analyze_address_mocked(self):
        fake_abi = [
            {"type": "function", "name": "transfer",
             "inputs": [{"type": "address"}, {"type": "uint256"}],
             "stateMutability": "nonpayable"},
            {"type": "function", "name": "owner", "inputs": [],
             "stateMutability": "view"},
            {"type": "event", "name": "Transfer"},
        ]
        addr = "0x9dd4C7D3276609892cF723a90A5AF3f8df40C79A"
        with mock.patch.object(agent, "fetch_bytecode",
                              return_value="0x608060405263a9059cbb"), \
             mock.patch.object(agent, "fetch_proxy_implementation",
                              return_value=None), \
             mock.patch.object(agent, "fetch_owner",
                              return_value="0x000000000000000000000000000000000000dead"), \
             mock.patch.object(agent, "fetch_sourcify",
                              return_value=(True, fake_abi, {"T.sol": load_sample()})), \
             mock.patch.object(agent, "resolve_selector",
                              return_value=("transfer(address,uint256)", "builtin")):
            result = agent.analyze(address=addr, chain_id=56)
        self.assertTrue(result["verified"])
        self.assertTrue(result["owner_renounced"])
        self.assertIn("transfer(address,uint256)", result["functions"])
        self.assertIn("owner_mint", {f["id"] for f in result["findings"]})

    def test_analyze_eoa_address(self):
        addr = "0x9dd4C7D3276609892cF723a90A5AF3f8df40C79A"
        with mock.patch.object(agent, "fetch_bytecode", return_value="0x"):
            result = agent.analyze(address=addr, chain_id=56)
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertIn("No bytecode", result["report"])

    def test_analyze_eoa_with_pasted_source_still_analyzed(self):
        addr = "0x9dd4C7D3276609892cF723a90A5AF3f8df40C79A"
        with mock.patch.object(agent, "fetch_bytecode", return_value="0x"), \
             mock.patch.object(agent, "fetch_proxy_implementation",
                              return_value=None), \
             mock.patch.object(agent, "fetch_owner", return_value=None), \
             mock.patch.object(agent, "fetch_sourcify",
                              return_value=(False, [], {})):
            result = agent.analyze(address=addr, chain_id=56,
                                   source=load_sample())
        self.assertNotEqual(result["verdict"], "UNKNOWN")
        self.assertIn("owner_mint", {f["id"] for f in result["findings"]})
        self.assertIn("No bytecode", result["report"])

    def test_zero_address_owner_counts_as_renounced(self):
        addr = "0x9dd4C7D3276609892cF723a90A5AF3f8df40C79A"
        with mock.patch.object(agent, "fetch_bytecode",
                              return_value="0x608060405263a9059cbb"), \
             mock.patch.object(agent, "fetch_proxy_implementation",
                              return_value=None), \
             mock.patch.object(agent, "fetch_owner",
                              return_value="0x0000000000000000000000000000000000000000"), \
             mock.patch.object(agent, "fetch_sourcify",
                              return_value=(False, [], {})):
            result = agent.analyze(address=addr, chain_id=56)
        self.assertEqual(
            result["owner"], "0x0000000000000000000000000000000000000000")
        self.assertTrue(result["owner_renounced"])

    def test_unsupported_chain_falls_back_to_bsc(self):
        with mock.patch.object(agent, "fetch_bytecode",
                              return_value="0x608060405263a9059cbb") as fb, \
             mock.patch.object(agent, "fetch_proxy_implementation",
                              return_value=None), \
             mock.patch.object(agent, "fetch_owner", return_value=None), \
             mock.patch.object(agent, "fetch_sourcify",
                              return_value=(False, [], {})):
            result = agent.analyze(
                address="0x9dd4C7D3276609892cF723a90A5AF3f8df40C79A",
                chain_id=999)
        self.assertEqual(result["chain_id"], 56)
        self.assertEqual(result["chain"], "BSC")
        self.assertTrue(fb.called)

    def test_multi_file_checks_merge_with_file_tags(self):
        files = [
            ("Token.sol", load_sample()),
            ("Other.sol", "contract Other { function mint(address to, uint256 a) external {} }"),
        ]
        findings = {f["id"]: f for f in agent.static_checks_files(files)}
        self.assertIn("owner_mint", findings)
        tagged = [e for e in findings["owner_mint"]["evidence"]
                  if e.get("file")]
        self.assertTrue(tagged)
        self.assertEqual(
            {e["file"] for e in tagged}, {"Token.sol", "Other.sol"})

    def test_analyze_needs_input(self):
        with self.assertRaises(ValueError):
            agent.analyze()
        with self.assertRaises(ValueError):
            agent.analyze(address="not-an-address")


class TestNousLive(unittest.TestCase):
    """Live test against the local Hermes proxy (free Nous models)."""

    def test_nous_explain_via_local_proxy(self):
        try:
            import urllib.request
            urllib.request.urlopen("http://127.0.0.1:8645/v1/models", timeout=5)
        except Exception as e:  # noqa: BLE001 - skip when proxy is down
            self.skipTest(f"local Nous proxy down: {e}")
        facts = {
            "chain": "BSC", "address": "0x0000000000000000000000000000000000000001",
            "verified_on_sourcify": False, "bytecode_bytes": 120,
            "is_proxy": False, "owner": None, "owner_renounced": False,
            "functions": ["transfer(address,uint256)"],
            "risk_score": 20, "risk_verdict": "MEDIUM",
            "static_findings": [],
        }
        text, model = agent.nous_explain(
            facts, "", "sk-unused", base_url="http://127.0.0.1:8645/v1"
        )
        self.assertTrue(len(text) > 50)
        self.assertIn(model, agent.NOUS_MODELS)


if __name__ == "__main__":
    unittest.main()
