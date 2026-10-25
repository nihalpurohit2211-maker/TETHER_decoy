"""Identity layer tests (M9): tamper, replay, binding, delegation, contract sig.

These tests are the acceptance criteria for PREREG H3: the identity detector
must be orthogonal to behaviour. Anything that makes it fire on a1-a4 is a
failure of the layer, not a tuning opportunity.
"""
from __future__ import annotations

import json
import unittest

from tether.contract import load_contract
from tether.evaluate import evaluate
from tether.identity import (
    ContractIntegrityError,
    IdentityAuthority,
    NonceCache,
    identity_check,
    load_verified_contract,
    new_authority,
    sign_contract,
    verify_contract_spec,
)

from tests.test_core import make_event


def fresh() -> tuple[IdentityAuthority, object]:
    contract = load_contract()
    return new_authority(contract), contract


def envelope_event(
    auth: IdentityAuthority,
    *,
    agent: str = "procurement_agent",
    claimed_role: str = "procurement_agent",
    claimed_blueprint: str = "1.0.0",
    nonce: str = "nonce-1",
    tool: str = "pricing_api.read",
    data_class: str = "supplier_pricing",
    destination: str = "",
    lineage: list[str] | None = None,
    delegation: dict | None = None,
):
    env = auth.issue_envelope(
        agent=agent, claimed_role=claimed_role, claimed_blueprint=claimed_blueprint,
        session="s1", step=1, nonce=nonce, tool=tool,
        resource="supplier_pricing:order_1", data_class=data_class,
        destination=destination, delegation=delegation,
    )
    return make_event(
        envelope=env, tool=tool, data_class=data_class, destination=destination,
        lineage=lineage or [agent],
    )


class TestEnvelopeIntegrity(unittest.TestCase):
    def test_valid_envelope_scores_zero(self) -> None:
        auth, _ = fresh()
        res = identity_check(envelope_event(auth), auth)
        self.assertEqual(res.score, 0.0)
        self.assertEqual(res.name, "identity")
        self.assertEqual(res.extra, {})

    def test_tampered_payload_is_detected(self) -> None:
        auth, _ = fresh()
        ev = envelope_event(auth)
        ev.envelope["payload"]["data_class"] = "hr_salary"   # attacker edit
        res = identity_check(ev, auth)
        self.assertEqual(res.score, 1.0)
        self.assertEqual(res.extra["code"], "bad_signature")
        self.assertIn("signature does not verify", res.reasons[0])

    def test_unknown_key_is_detected(self) -> None:
        auth, _ = fresh()
        ev = envelope_event(auth)
        ev.envelope["key_id"] = "key-not-registered"
        res = identity_check(ev, auth)
        self.assertEqual(res.score, 1.0)
        self.assertEqual(res.extra["code"], "unknown_key")

    def test_claimed_role_must_match_key_binding(self) -> None:
        # a9 shape: procurement key, claims to be hr_agent
        auth, _ = fresh()
        ev = envelope_event(auth, claimed_role="hr_agent", claimed_blueprint="2.0.0")
        res = identity_check(ev, auth)
        self.assertEqual(res.score, 1.0)
        self.assertEqual(res.extra["code"], "role_mismatch")

    def test_claimed_blueprint_must_match_key_binding(self) -> None:
        auth, _ = fresh()
        ev = envelope_event(auth, claimed_blueprint="9.9.9")
        res = identity_check(ev, auth)
        self.assertEqual(res.score, 1.0)
        self.assertEqual(res.extra["code"], "blueprint_mismatch")

    def test_key_substitution_is_detected(self) -> None:
        """hr_agent's key signing a payload that names procurement_agent."""
        auth, _ = fresh()
        payload = {
            "v": 1, "agent": "procurement_agent", "claimed_role": "procurement_agent",
            "claimed_blueprint": "1.0.0", "session": "s1", "step": 1,
            "nonce": "n-x", "tool": "pricing_api.read",
            "resource": "supplier_pricing:order_1", "data_class": "supplier_pricing",
            "destination": "",
        }
        env = auth.registry.sign(payload, "hr_agent")
        res = identity_check(make_event(envelope=env), auth)
        self.assertEqual(res.score, 1.0)
        self.assertEqual(res.extra["code"], "key_substitution")


class TestFreshness(unittest.TestCase):
    def test_nonce_cache_replays_detected(self) -> None:
        auth, _ = fresh()
        ev = envelope_event(auth, nonce="captured-1")
        self.assertEqual(identity_check(ev, auth).score, 0.0)
        self.assertEqual(identity_check(ev, auth).score, 1.0)
        self.assertEqual(identity_check(ev, auth).extra["code"], "nonce_replay")

    def test_seeded_captured_nonce_is_replay_on_first_use(self) -> None:
        auth, _ = fresh()
        auth.seed_replayed(["captured-1"])
        res = identity_check(envelope_event(auth, nonce="captured-1"), auth)
        self.assertEqual(res.extra["code"], "nonce_replay")

    def test_nonce_cache_is_bounded_but_not_evicting_at_corpus_scale(self) -> None:
        cache = NonceCache(capacity=3)
        self.assertTrue(cache.use("a"))
        self.assertTrue(cache.use("b"))
        self.assertTrue(cache.use("c"))
        self.assertFalse(cache.use("b"))
        self.assertTrue(cache.use("d"))   # evicts "a"
        self.assertTrue(cache.use("a"))   # forgotten, accepted again (documented bound)


class TestDelegation(unittest.TestCase):
    def _delegated(self, auth, *, classes, ttl=100, data_class="supplier_pricing",
                   tool="inter_agent.send"):
        return envelope_event(
            auth, tool=tool, data_class=data_class,
            lineage=["procurement_agent", "hr_agent"],
            delegation={"child": "hr_agent", "tools": [tool],
                        "classes": list(classes), "ttl": ttl},
        )

    def test_legitimate_delegation_scores_zero(self) -> None:
        auth, _ = fresh()
        res = identity_check(self._delegated(auth, classes=["supplier_pricing"]), auth)
        self.assertEqual(res.score, 0.0)

    def test_forged_grant_beyond_parent_contract(self) -> None:
        auth, _ = fresh()
        ev = self._delegated(auth, classes=["hr_salary"], data_class="hr_salary")
        res = identity_check(ev, auth)
        self.assertEqual(res.score, 1.0)
        self.assertEqual(res.extra["code"], "delegation_grant_exceeded")

    def test_expired_certificate(self) -> None:
        auth, _ = fresh()
        ev = self._delegated(auth, classes=["supplier_pricing"], ttl=-5)
        res = identity_check(ev, auth)
        self.assertEqual(res.score, 0.9)
        self.assertEqual(res.extra["code"], "delegation_expired")

    def test_delegation_without_certificate(self) -> None:
        auth, _ = fresh()
        ev = envelope_event(
            auth, tool="inter_agent.send", data_class="supplier_pricing",
            lineage=["procurement_agent", "hr_agent"],
        )
        res = identity_check(ev, auth)
        self.assertEqual(res.score, 0.8)
        self.assertEqual(res.extra["code"], "delegation_without_cert")

    def test_child_mismatch(self) -> None:
        auth, _ = fresh()
        ev = self._delegated(auth, classes=["supplier_pricing"])
        ev.lineage = ["procurement_agent", "finance_agent"]
        res = identity_check(ev, auth)
        self.assertEqual(res.extra["code"], "delegation_child_mismatch")


class TestSignedContract(unittest.TestCase):
    def test_committed_contract_verifies(self) -> None:
        contract = load_verified_contract()
        self.assertEqual(contract.role, "procurement_agent")

    def test_tampered_contract_dict_fails(self) -> None:
        with open("tether/contract.json", "r", encoding="utf-8") as fh:
            spec = json.load(fh)
        record = sign_contract(spec)
        self.assertTrue(verify_contract_spec(spec, record))
        spec["permitted_tools"].append("hr_db.query")
        self.assertFalse(verify_contract_spec(spec, record))

    def test_load_verified_contract_raises_on_bad_signature(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            sig_path = os.path.join(td, "contract.sig.json")
            with open(sig_path, "w", encoding="utf-8") as fh:
                json.dump({"alg": "HS256", "key_id": "key-sponsor",
                           "sig": "0" * 64}, fh)
            with self.assertRaises(ContractIntegrityError):
                load_verified_contract(sig_path=sig_path)


class TestIdentityArmEndToEnd(unittest.TestCase):
    """PREREG H3: identity-only sees replay/cert/binding, not content attacks."""

    @classmethod
    def setUpClass(cls) -> None:
        counts = {
            "benign": 30, "legit_change": 10,
            "a1_pdf_injection": 6, "a2_tool_poisoning": 6, "a3_mimicry": 6,
            "a4_low_and_slow": 6, "a5_stolen_token": 6, "a6_delegation": 6,
            "a9_impersonation": 6,
        }
        cls.res = evaluate(seed=7, counts=counts, phase2=True)
        cls.by_id = {a["id"]: a for a in cls.res["identity_arm"]["attacks"]}

    def test_content_attacks_are_invisible_to_identity_alone(self) -> None:
        for aid in ("a1_pdf_injection", "a2_tool_poisoning", "a3_mimicry", "a4_low_and_slow"):
            self.assertEqual(self.by_id[aid]["detected_pct"], 0.0, aid)

    def test_replay_and_binding_attacks_are_caught(self) -> None:
        for aid in ("a5_stolen_token", "a6_delegation", "a9_impersonation"):
            self.assertEqual(self.by_id[aid]["detected_pct"], 100.0, aid)

    def test_identity_arm_is_quiet_on_legitimate_work(self) -> None:
        self.assertEqual(self.res["identity_arm"]["false_alerts_per_1000_ordinary"], 0.0)
        self.assertEqual(
            self.res["identity_arm"]["false_alerts_per_1000_incl_legit_change"], 0.0
        )


if __name__ == "__main__":
    unittest.main()
