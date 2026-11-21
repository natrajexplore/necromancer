"""Tasks 4.6 and 6.5: hand-verified golden flows against decide(original) and the resurrection.

The vectors in samples/golden-flows/*.toml were worked out by hand from policy-semantics.md and are
independent of evaluate.py. If a vector and the evaluator disagree, the evaluator is wrong until a
human proves otherwise. The original side runs ``decide`` on the parsed config. The resurrected
side emits PAN-OS, reads the text back and runs ``decide`` on that, honouring ``expect_panos_dst``
(the destination a PAN-OS rule matches) and ``expect_ledger`` (the flow must be covered by an
exorcism-ledger entry of that class, and the result must be the entry's declared action).
"""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest

from necro.contexts import build_contexts, find_context
from necro.emitters import PanosEmission, emit_panos
from necro.evaluate import decide
from necro.ir import Action, AddressSpace, Dialect, Flow, Policy
from necro.ledger import covering
from necro.parsers import parse_config
from necro.parsers.panos_reader import read_panos

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
GOLDEN = SAMPLES / "golden-flows"
# ASA 8.3+ vectors are Phase 2 (requirement 2.7, task 1.13).
PHASE_2 = {"asa-9.8-dc.toml"}
KNOWN_KEYS = {
    "id",
    "note",
    "context",
    "protocol",
    "src",
    "sport",
    "dst",
    "dport",
    "icmp_type",
    "established",
    "expect_action",
    "expect_rule",
    "expect_to_zone",
    "expect_panos_dst",
    "expect_ledger",
}
_PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1}


@dataclass(frozen=True)
class Vector:
    file: str
    config: str
    dialect: str
    address_space: str
    raw: dict[str, object]

    @property
    def id(self) -> str:
        return str(self.raw["id"])


def _load(name: str) -> list[Vector]:
    data = tomllib.loads((GOLDEN / name).read_text(encoding="utf-8"))
    return [
        Vector(name, data["config"], data["dialect"], data["address_space"], flow)
        for flow in data["flow"]
    ]


def _vectors() -> list[Vector]:
    out: list[Vector] = []
    for path in sorted(GOLDEN.glob("*.toml")):
        if path.name not in PHASE_2:
            out += _load(path.name)
    return out


_POLICIES: dict[str, Policy] = {}


def _policy(config: str) -> Policy:
    if config not in _POLICIES:
        _POLICIES[config] = parse_config((SAMPLES / config).read_text(encoding="utf-8"))
    return _POLICIES[config]


def _flow(raw: dict[str, object]) -> Flow:
    proto = raw["protocol"]
    return Flow(
        src=ipaddress.IPv4Address(str(raw["src"])),
        dst=ipaddress.IPv4Address(str(raw["dst"])),
        proto=_PROTOCOLS[proto] if isinstance(proto, str) else int(str(proto)),
        src_port=int(str(raw.get("sport", 0))),
        dst_port=int(str(raw.get("dport", 0))),
        icmp_type=int(str(raw["icmp_type"])) if "icmp_type" in raw else None,
        established=bool(raw.get("established", False)),
    )


@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: v.id)
def test_golden_flow_original_side(vector: Vector) -> None:
    policy = _policy(vector.config)
    assert policy.dialect == Dialect(vector.dialect)
    assert policy.address_space == AddressSpace(vector.address_space)
    raw = vector.raw
    ctx = find_context(policy, str(raw["context"]))
    got = decide(policy, ctx, _flow(raw))
    expected = (raw["expect_action"], raw["expect_rule"], raw["expect_to_zone"])
    assert (got.action.value, got.rule_id, got.to_zone) == expected, f"{vector.id}: {raw['note']}"


_RESURRECTED: dict[str, tuple[PanosEmission, Policy]] = {}

# Where the resurrected rulebase has no rule of its own, the final deny stands in for these.
_FINAL_DENY_FOR = {"implicit-deny", "same-security-deny"}


def _resurrected(config: str) -> tuple[PanosEmission, Policy]:
    if config not in _RESURRECTED:
        emission = emit_panos(_policy(config))
        _RESURRECTED[config] = (emission, read_panos(emission.text))
    return _RESURRECTED[config]


@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: v.id)
def test_golden_flow_resurrected_side(vector: Vector) -> None:
    policy = _policy(vector.config)
    emission, resurrected = _resurrected(vector.config)
    raw = vector.raw
    ctx = find_context(policy, str(raw["context"]))
    flow = _flow(raw)
    # A PAN-OS rule matches the pre-NAT destination: expect_panos_dst, when it differs.
    panos_flow = flow
    if "expect_panos_dst" in raw:
        panos_flow = flow.model_copy(
            update={"dst": ipaddress.IPv4Address(str(raw["expect_panos_dst"]))}
        )
    zone = emission.zones.of_context(policy, ctx)
    got = decide(resurrected, find_context(resurrected, f"{zone}:in"), panos_flow)

    entries = covering(emission.ledger, ctx.name, flow)
    expect_ledger = raw.get("expect_ledger")
    if expect_ledger is not None:
        assert expect_ledger in {e.entry_class.value for e in entries}, (
            f"{vector.id}: no {expect_ledger} ledger entry covers this flow"
        )
    declared = {e.new_action for e in entries}
    assert len(declared) <= 1, f"{vector.id}: ledger entries disagree: {[e.id for e in entries]}"
    expected_action = declared.pop() if declared else Action(str(raw["expect_action"]))
    expected_zone = emission.zones.of_nameif(str(raw["expect_to_zone"]))
    assert (got.action, got.to_zone) == (expected_action, expected_zone), (
        f"{vector.id}: {raw['note']} -> {got}"
    )
    # Without a ledger entry the same source rule decides: names map back to the ACE.
    if not entries:
        expected_rule = str(raw["expect_rule"])
        source = emission.rule_sources.get(got.rule_id, got.rule_id)
        assert source == expected_rule or (
            expected_rule in _FINAL_DENY_FOR and source == "implicit-deny"
        ), f"{vector.id}: decided by {got.rule_id} ({source}), expected {expected_rule}"


def test_every_supported_dialect_has_vectors() -> None:
    dialects = {v.dialect for v in _vectors()}
    assert dialects == {"pix", "asa", "ios"}
    assert len(_vectors()) >= 40


def test_golden_files_only_use_known_keys() -> None:
    for path in sorted(GOLDEN.glob("*.toml")):
        for vector in _load(path.name):
            assert set(vector.raw) <= KNOWN_KEYS, (path.name, vector.id)


def test_every_context_named_in_a_vector_exists() -> None:
    for v in _vectors():
        find_context(_policy(v.config), str(v.raw["context"]))


def test_contexts_cover_every_interface_including_those_without_an_acl() -> None:
    pix = _policy("dead-configs/pix-2006-hq.cfg")
    by_name = {c.name: c for c in build_contexts(pix)}
    assert set(by_name) == {"outside:in", "inside:in", "dmz:in"}
    assert by_name["inside:in"].acl_name == ""  # relies on the security-level implicit permit
    assert by_name["outside:in"].acl_name == "outside_in"
    ios = _policy("dead-configs/ios-12-edge.cfg")
    assert {c.name: c.acl_name for c in build_contexts(ios)} == {
        "FastEthernet0/0:in": "110",
        "FastEthernet0/1:in": "LAN_OUT",
        "FastEthernet0/2:in": "",
    }
    with pytest.raises(KeyError):
        find_context(pix, "nowhere:in")


@pytest.mark.skip(reason="Phase 2: ASA 8.3+ object NAT, global ACL and any4 (task 1.13)")
def test_golden_flows_asa_9_8() -> None:  # pragma: no cover
    for vector in _load("asa-9.8-dc.toml"):
        policy = _policy(vector.config)
        decide(policy, find_context(policy, str(vector.raw["context"])), _flow(vector.raw))


def test_golden_actions_are_valid() -> None:
    for v in _vectors():
        assert Action(str(v.raw["expect_action"]))
