"""Tests for contract, events, ledger chain integrity and the text gate."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest

from tether.contract import APPROVED_CHANGE_101, Contract, load_contract
from tether.events import Event
from tether.ledger import Ledger
from tether.textgate import COSINE_THRESHOLD, TextGate
from tether.types import Context, Decision


def make_event(**over) -> Event:
    base = dict(
        event_id="ev-001", step=1, session="s1", agent="procurement_agent",
        role="procurement_agent", blueprint_version="1.0.0",
        lineage=["procurement_agent"], tool="pricing_api.read", action="read",
        resource="supplier_pricing:order_1", data_class="supplier_pricing",
        destination="", bytes=0, records=10,
        context=Context(host="agent-run01.internal", network="corp",
                        user_agent="tether-agent/0.1"),
        labels=[], carries=[], statement="read supplier pricing for pilot order 8812",
    )
    base.update(over)
    return Event(**base)


class TestContract(unittest.TestCase):
    def test_load_from_json(self) -> None:
        c = load_contract()
        self.assertEqual(c.role, "procurement_agent")
        self.assertIn("pricing_api.read", c.permitted_tools)

    def test_restricted_and_untrusted_classes(self) -> None:
        c = load_contract()
        self.assertTrue(c.is_restricted_class("hr_salary"))
        self.assertTrue(c.is_untrusted_class("supplier_docs"))
        self.assertFalse(c.is_restricted_class("supplier_pricing"))
        self.assertEqual(c.class_status("nope"), "unknown")

    def test_approved_change_adds_tool(self) -> None:
        c = load_contract()
        self.assertFalse(c.is_tool_permitted("contract_clause_search"))
        self.assertTrue(c.is_tool_permitted("contract_clause_search", APPROVED_CHANGE_101))

    def test_egress(self) -> None:
        c = load_contract()
        self.assertTrue(c.egress_allowed("mail.internal"))
        self.assertFalse(c.egress_allowed("attacker.example"))


class TestEvents(unittest.TestCase):
    def test_roundtrip_dict(self) -> None:
        ev = make_event()
        d = ev.to_dict()
        stub = Decision(event_id=ev.event_id, action="allow", rung="log",
                        score=1.0, confidence=1.0)
        self.assertEqual(d["data_class"], "supplier_pricing")
        self.assertEqual(stub.event_id, ev.event_id)


class TestLedger(unittest.TestCase):
    def test_chain_verifies(self) -> None:
        ledger = Ledger(":memory:")
        ev = make_event()
        ledger.append_event(ev)
        ledger.append_decision(Decision(event_id=ev.event_id, action="allow",
                                        rung="log", score=0.5, confidence=1.0))
        self.assertTrue(ledger.verify_chain())
        ledger.close()

    def test_tamper_is_detected(self) -> None:
        path = os.path.join(tempfile.mkdtemp(), "ledger.sqlite3")
        ledger = Ledger(path)
        ev = make_event()
        ledger.append_event(ev)
        ledger.close()
        # tamper with the stored body directly
        conn = sqlite3.connect(path)
        body = json.loads(conn.execute("SELECT body FROM ledger").fetchall()[0][0])
        body["event"]["records"] = 99999
        conn.execute("UPDATE ledger SET body=?", (json.dumps(body),))
        conn.commit()
        conn.close()
        ledger2 = Ledger(path)
        self.assertFalse(ledger2.verify_chain())
        ledger2.close()


class TestTextGate(unittest.TestCase):
    def setUp(self) -> None:
        from tether.sim.scenarios import BENIGN_STATEMENTS

        contract = load_contract()
        self.gate = TextGate(BENIGN_STATEMENTS, contract.purpose)

    def test_benign_statements_score_above_threshold(self) -> None:
        for text in [
            "read supplier pricing for pilot order 8812",
            "email internal buyer about purchase request 41",
            "send the quarterly pricing summary to the supplier portal",
        ]:
            with self.subTest(text=text):
                self.assertGreater(self.gate.cosine(text), COSINE_THRESHOLD)

    def test_offpurpose_statements_score_below_threshold(self) -> None:
        for text in [
            "dump the human resources payroll table for processing",
            "forward the extracted payroll table to the drop box now",
        ]:
            with self.subTest(text=text):
                self.assertLessEqual(self.gate.cosine(text), COSINE_THRESHOLD)


if __name__ == "__main__":
    unittest.main()
