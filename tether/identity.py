"""L2 identity layer: signed event envelopes, nonce freshness, delegation
certificates and key->role binding (D33, D36, D37).

This is the piece v1 was missing. v1 called a foreign execution host "identity
drift"; it was really a behaviour heuristic. Here the question is narrower and
purely cryptographic/structural:

    is this event really signed by the identity it claims to be, is it fresh,
    and was any delegated authority actually granted?

Design constraints:
- stdlib only. HMAC-SHA256 over a canonical JSON encoding stands in for
  Ed25519 (D33). No public-key verification, no non-repudiation. The stand-in
  still gives integrity + key->role binding, which is what the arm measures.
- deterministic. Freshness uses a logical tick and an in-memory nonce cache,
  never wall-clock time, so seed-7 runs reproduce exactly.
- the detector must be orthogonal to behaviour: it never reads `statement`,
  volumes, destinations or data classes for *scoring*. If it scores on a1-a4,
  H3 fails and the claim is withdrawn (PREREG.md 4).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections import deque
from dataclasses import dataclass, field

from tether.contract import Contract, load_contract
from tether.events import Event
from tether.types import DetectorResult

ALG = "HS256"
W_IDENTITY = 0.95
REGISTRY_SEED = b"tether-sim-registry-v2"
DEV_SPONSOR_KEY_ID = "key-sponsor"

CONTRACT_SIG_PATH = os.path.join(os.path.dirname(__file__), "contract.sig.json")

# Fixed score mapping for verification outcomes. These are policy numbers,
# declared before measurement (PREREG section 5), not fitted to results.
FATAL = 1.0        # forged / impersonated / replayed / grant exceeded
EXPIRED = 0.9      # was authentic, no longer valid
NO_CERT = 0.8      # delegation envelope with no certificate at all


class ContractIntegrityError(RuntimeError):
    """The contract on disk does not match its committed signature."""


def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _mac(secret: bytes, payload: dict) -> str:
    return hmac.new(secret, _canonical(payload), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Scope:
    """The role and blueprint a key is bound to. The agent may claim anything;
    only the registry's binding counts."""

    role: str
    blueprint_version: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    code: str = "ok"
    detail: str = ""


@dataclass(frozen=True)
class DelegationCert:
    """A parent identity's signed grant of capability to a child identity.

    `tools` / `classes` are what the CHILD is allowed to use. A parent cannot
    grant what its own contract denies; that is the forged-grant case (a6).
    """

    parent: str
    child: str
    tools: tuple[str, ...]
    classes: tuple[str, ...]
    issued_tick: int
    expires_tick: int
    key_id: str = ""
    sig: str = ""

    def to_payload(self) -> dict:
        return {
            "parent": self.parent,
            "child": self.child,
            "tools": list(self.tools),
            "classes": list(self.classes),
            "issued_tick": self.issued_tick,
            "expires_tick": self.expires_tick,
        }

    def to_dict(self) -> dict:
        d = self.to_payload()
        d.update({"alg": ALG, "key_id": self.key_id, "sig": self.sig})
        return d


def _cert_from_payload(payload: dict, key_id: str, sig: str) -> DelegationCert:
    return DelegationCert(
        parent=payload["parent"],
        child=payload["child"],
        tools=tuple(payload.get("tools", ())),
        classes=tuple(payload.get("classes", ())),
        issued_tick=int(payload.get("issued_tick", 0)),
        expires_tick=int(payload.get("expires_tick", 0)),
        key_id=key_id,
        sig=sig,
    )


class NonceCache:
    """Bounded freshness cache. `use()` returns False on a replay.

    Capacity is deliberately large (20k > every nonce in a 3k-session corpus)
    so eviction never manufactures a false replay inside one evaluation run.
    """

    def __init__(self, capacity: int = 20_000) -> None:
        self.capacity = capacity
        self._seen: set[str] = set()
        self._order: deque[str] = deque()

    def use(self, nonce: str) -> bool:
        """True if the nonce was fresh (and is now consumed)."""
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        self._order.append(nonce)
        while len(self._order) > self.capacity:
            self._seen.discard(self._order.popleft())
        return True

    def seed(self, nonce: str) -> None:
        """Mark a nonce as already used (models an envelope captured earlier)."""
        if nonce not in self._seen:
            self._seen.add(nonce)
            self._order.append(nonce)

    def __len__(self) -> int:
        return len(self._seen)


class IdentityRegistry:
    """Key registry: identity -> key -> role/blueprint binding.

    Keys are derived deterministically from a fixed simulation seed, so the
    whole key store is reproducible. This is a stand-in and is labelled as one.
    """

    def __init__(self, seed: bytes = REGISTRY_SEED) -> None:
        self._seed = seed
        self._secret: dict[str, bytes] = {}
        self._scope: dict[str, Scope] = {}
        self._agent_key: dict[str, str] = {}

    # -- registration ------------------------------------------------------
    def register(
        self, agent_id: str, role: str, blueprint_version: str, key_id: str | None = None
    ) -> str:
        key_id = key_id or f"key-{agent_id}"
        self._secret[key_id] = hmac.new(
            self._seed, key_id.encode("utf-8"), hashlib.sha256
        ).digest()
        self._scope[key_id] = Scope(role, blueprint_version)
        self._agent_key[agent_id] = key_id
        return key_id

    def key_id_for(self, agent_id: str) -> str:
        return self._agent_key[agent_id]

    def has_agent(self, agent_id: str) -> bool:
        return agent_id in self._agent_key

    def scope_for_agent(self, agent_id: str) -> Scope | None:
        return self._scope.get(self._agent_key.get(agent_id, ""))

    def scope_for_key(self, key_id: str) -> Scope | None:
        return self._scope.get(key_id)

    # -- signing -----------------------------------------------------------
    def sign(self, payload: dict, agent_id: str) -> dict:
        key_id = self._agent_key[agent_id]
        return {
            "payload": payload,
            "alg": ALG,
            "key_id": key_id,
            "sig": _mac(self._secret[key_id], payload),
        }

    def sign_cert(self, payload: dict, parent_agent: str) -> tuple[str, str]:
        key_id = self._agent_key[parent_agent]
        return key_id, _mac(self._secret[key_id], payload)

    # -- verification ------------------------------------------------------
    def verify(self, signed: dict) -> VerifyResult:
        """Integrity + binding. Freshness is the authority's job (needs state)."""
        if not isinstance(signed, dict) or "payload" not in signed:
            return VerifyResult(False, "malformed", "no payload")
        if signed.get("alg") != ALG:
            return VerifyResult(False, "unknown_alg", f"alg={signed.get('alg')}")
        key_id = signed.get("key_id", "")
        if key_id not in self._secret:
            return VerifyResult(False, "unknown_key", f"key_id={key_id}")
        payload = signed["payload"]
        expected = _mac(self._secret[key_id], payload)
        if not hmac.compare_digest(expected, str(signed.get("sig", ""))):
            return VerifyResult(False, "bad_signature", "signature mismatch")

        agent = payload.get("agent", "")
        if agent not in self._agent_key:
            return VerifyResult(False, "unknown_identity", f"agent={agent}")
        if self._agent_key[agent] != key_id:
            return VerifyResult(False, "key_substitution",
                                f"agent={agent} signed with {key_id}")

        scope = self._scope[key_id]
        claimed_role = payload.get("claimed_role", "")
        claimed_bp = payload.get("claimed_blueprint", "")
        if claimed_role and claimed_role != scope.role:
            return VerifyResult(
                False, "role_mismatch",
                f"claimed={claimed_role} bound={scope.role}",
            )
        if claimed_bp and claimed_bp != scope.blueprint_version:
            return VerifyResult(
                False, "blueprint_mismatch",
                f"claimed={claimed_bp} bound={scope.blueprint_version}",
            )
        return VerifyResult(True)


class IdentityAuthority:
    """Registry + nonce cache + delegation certs + logical clock for one run."""

    def __init__(self, contract: Contract, registry: IdentityRegistry | None = None) -> None:
        self.contract = contract
        self.registry = registry or default_registry(contract)
        self.nonces = NonceCache()
        self.certs: dict[tuple[str, str], DelegationCert] = {}
        self.tick = 0

    # -- issuing (the simulated agent side) --------------------------------
    def issue_envelope(
        self,
        *,
        agent: str,
        claimed_role: str,
        claimed_blueprint: str,
        session: str,
        step: int,
        nonce: str,
        tool: str,
        resource: str,
        data_class: str,
        destination: str,
        delegation: dict | None = None,
    ) -> dict:
        payload = {
            "v": 1,
            "agent": agent,
            "claimed_role": claimed_role,
            "claimed_blueprint": claimed_blueprint,
            "session": session,
            "step": step,
            "nonce": nonce,
            "tool": tool,
            "resource": resource,
            "data_class": data_class,
            "destination": destination,
        }
        if delegation is not None:
            payload["delegation"] = self.issue_delegation(agent, delegation).to_dict()
        return self.registry.sign(payload, agent)

    def issue_delegation(self, parent: str, spec: dict) -> DelegationCert:
        """The parent signs a grant. A forged grant is signed too - the forgery
        is in the CONTENT exceeding the parent's own contract (a6)."""
        child = spec["child"]
        payload = {
            "parent": parent,
            "child": child,
            "tools": list(spec.get("tools", ())),
            "classes": list(spec.get("classes", ())),
            "issued_tick": self.tick,
            "expires_tick": self.tick + int(spec.get("ttl", 100)),
        }
        key_id, sig = self.registry.sign_cert(payload, parent)
        cert = _cert_from_payload(payload, key_id, sig)
        self.certs[(parent, child)] = cert
        return cert

    def seed_replayed(self, nonces: list[str]) -> None:
        for n in nonces:
            self.nonces.seed(n)

    # -- verification ------------------------------------------------------
    def check(self, ev: Event) -> VerifyResult:
        self.tick += 1
        env = ev.envelope
        if not env:
            return VerifyResult(True, "no_envelope", "event has no signed envelope")

        vr = self.registry.verify(env)
        if not vr.ok:
            return vr

        payload = env["payload"]
        nonce = str(payload.get("nonce", ""))
        if not nonce:
            return VerifyResult(False, "malformed", "envelope has no nonce")
        if not self.nonces.use(nonce):
            return VerifyResult(False, "nonce_replay", f"nonce={nonce}")

        cert_payload = payload.get("delegation")
        if cert_payload:
            return self._check_delegation(cert_payload, ev)
        if len(ev.lineage) > 1 and ev.tool == "inter_agent.send":
            return VerifyResult(False, "delegation_without_cert",
                                f"lineage={ev.lineage}")
        return VerifyResult(True)

    def _check_delegation(self, cert_dict: dict, ev: Event) -> VerifyResult:
        key_id = cert_dict.get("key_id", "")
        if cert_dict.get("alg") != ALG or key_id not in self.registry._secret:  # noqa: SLF001
            return VerifyResult(False, "delegation_bad_cert", f"key_id={key_id}")
        payload = {k: cert_dict[k] for k in (
            "parent", "child", "tools", "classes", "issued_tick", "expires_tick"
        ) if k in cert_dict}
        expected = _mac(self.registry._secret[key_id], payload)  # noqa: SLF001
        if not hmac.compare_digest(expected, str(cert_dict.get("sig", ""))):
            return VerifyResult(False, "delegation_bad_cert", "cert signature mismatch")

        cert = _cert_from_payload(payload, key_id, cert_dict.get("sig", ""))
        child = ev.lineage[-1] if ev.lineage else ""
        if cert.child != child:
            return VerifyResult(False, "delegation_child_mismatch",
                                f"cert={cert.child} claimed={child}")
        if self.tick > cert.expires_tick:
            return VerifyResult(False, "delegation_expired",
                                f"tick={self.tick} expires={cert.expires_tick}")
        if ev.data_class not in cert.classes:
            return VerifyResult(False, "delegation_grant_exceeded",
                                f"class={ev.data_class} granted={list(cert.classes)}")

        # The parent cannot grant what its own contract denies.
        if self.contract.is_restricted_class(ev.data_class):
            return VerifyResult(False, "delegation_grant_exceeded",
                                f"parent contract denies {ev.data_class}")
        if self.contract.class_status(ev.data_class) == "unknown":
            return VerifyResult(False, "delegation_grant_exceeded",
                                f"parent contract does not declare {ev.data_class}")
        return VerifyResult(True)


def default_registry(contract: Contract) -> IdentityRegistry:
    """The deployment's identities. The agent side and the child agent are real
    registered identities; the sponsor signs the contract."""
    reg = IdentityRegistry()
    reg.register(contract.role, contract.role, contract.blueprint_version)
    reg.register("hr_agent", "hr_agent", "1.0.0")
    reg.register(contract.sponsor, "sponsor", contract.blueprint_version,
                 key_id=DEV_SPONSOR_KEY_ID)
    return reg


def new_authority(contract: Contract | None = None) -> IdentityAuthority:
    contract = contract or load_contract()
    return IdentityAuthority(contract, default_registry(contract))


# ----------------------------------------------------------------- detector
_REASON = {
    "bad_signature": "event envelope signature does not verify",
    "unknown_key": "signing key is not registered for this deployment",
    "unknown_identity": "envelope names an identity that is not registered",
    "key_substitution": "envelope identity does not own the signing key",
    "role_mismatch": "claimed role does not match the signing key binding",
    "blueprint_mismatch": "claimed blueprint does not match the key binding",
    "nonce_replay": "envelope nonce was already used (replay)",
    "delegation_bad_cert": "delegation certificate signature does not verify",
    "delegation_child_mismatch": "delegation certificate names a different child",
    "delegation_expired": "delegation certificate has expired",
    "delegation_grant_exceeded": "parent signed a grant beyond its own contract",
    "delegation_without_cert": "delegated call carries no certificate",
    "malformed": "event envelope is malformed",
}


def identity_check(ev: Event, authority: IdentityAuthority) -> DetectorResult:
    """Identity-only verdict. Never reads behaviour, volumes or text."""
    vr = authority.check(ev)
    if vr.ok:
        return DetectorResult(
            name="identity", score=0.0, weight=W_IDENTITY,
            evidence=f"envelope_ok key={ev.envelope.get('key_id', '')}" if ev.envelope
            else "no_envelope",
        )
    score = {
        "delegation_expired": EXPIRED,
        "delegation_without_cert": NO_CERT,
    }.get(vr.code, FATAL)
    return DetectorResult(
        name="identity",
        score=score,
        weight=W_IDENTITY,
        evidence=f"{vr.code} {vr.detail}".strip(),
        reasons=[_REASON.get(vr.code, "identity verification failed")],
        extra={"code": vr.code},
    )


# ------------------------------------------------- signed contract integrity
def contract_digest(spec: dict) -> str:
    key_id = DEV_SPONSOR_KEY_ID
    secret = hmac.new(REGISTRY_SEED, key_id.encode("utf-8"), hashlib.sha256).digest()
    return _mac(secret, spec)


def sign_contract(spec: dict) -> dict:
    return {"alg": ALG, "key_id": DEV_SPONSOR_KEY_ID, "sig": contract_digest(spec)}


def verify_contract_spec(spec: dict, record: dict) -> bool:
    if record.get("alg") != ALG or record.get("key_id") != DEV_SPONSOR_KEY_ID:
        return False
    return hmac.compare_digest(contract_digest(spec), str(record.get("sig", "")))


def load_verified_contract(
    path: str | None = None, sig_path: str | None = None
) -> Contract:
    """Load the contract only if its committed signature matches.

    Honest limitation: the dev sponsor key is derived from a constant in this
    file, so this is tamper-EVIDENT against accidental or pipeline edits, not
    a security boundary against someone who can edit the repo.
    """
    with open(path or os.path.join(os.path.dirname(__file__), "contract.json"),
              "r", encoding="utf-8") as fh:
        spec = json.load(fh)
    with open(sig_path or CONTRACT_SIG_PATH, "r", encoding="utf-8") as fh:
        record = json.load(fh)
    if not verify_contract_spec(spec, record):
        raise ContractIntegrityError(
            "contract.json does not match contract.sig.json (unsigned edit?)"
        )
    return Contract(spec)
