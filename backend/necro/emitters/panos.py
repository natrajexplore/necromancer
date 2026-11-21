"""PAN-OS ``set``-command emitter (requirements 4.1-4.14).

``emit_panos(policy)`` turns a parsed ``Policy`` into a candidate configuration. It reads the IR
only, never raw config, and never contacts a device. Output is deterministic: sections come in a
fixed order and every section is sorted by name, except the rulebase, which keeps source order.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from necro.contexts import build_contexts
from necro.emitters.panos_env import BuildEnv
from necro.emitters.panos_mgmt import plan_management, profile_lines, to_the_box_entries
from necro.emitters.panos_names import NameRegistry
from necro.emitters.panos_nat import nat_lines
from necro.emitters.panos_network import ZoneMap, device_addresses, network_lines
from necro.emitters.panos_objects import ANY, ObjectTable, name_list, name_token
from necro.emitters.panos_rules import (
    TAG_FINAL_DENY,
    TAG_IMPLICIT,
    RuleSpec,
    context_specs,
    final_deny_spec,
)
from necro.ir import Action, Dialect, Policy
from necro.ledger import LedgerEntry, number_entries
from necro.nat import NatModel
from necro.zones import build_route_table

_LOG_END = "log-end yes"
_TAG_COMMENTS = {
    TAG_IMPLICIT: "Reproduces an implicit permit of the source device",
    TAG_FINAL_DENY: "Explicit final deny so behaviour does not depend on PAN-OS defaults",
}


@dataclass
class PanosEmission:
    """The candidate configuration plus everything a reviewer needs to judge it."""

    lines: list[str]
    zones: ZoneMap
    rule_sources: dict[str, str] = field(default_factory=dict)  # PAN-OS rule name -> source rule id
    unsupported: list[str] = field(default_factory=list)  # not expressed; blocks the verdict
    notes: list[str] = field(default_factory=list)  # differences that change no decision
    ledger: list[LedgerEntry] = field(default_factory=list)  # expressed lossily, on the record

    @property
    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def _tag_lines(specs: list[RuleSpec]) -> list[str]:
    tags = sorted({t for s in specs for t in s.tags})
    lines: list[str] = []
    for tag in tags:
        comment = _TAG_COMMENTS.get(tag)
        if comment is None and tag.startswith("src-acl:"):
            comment = f"Source ACL {tag.removeprefix('src-acl:')}"
        lines.append(f'set tag {name_token(tag)} comments "{comment or tag}"')
    return lines


def _quote_text(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _rule_lines(name: str, spec: RuleSpec, objects: ObjectTable) -> list[str]:
    head = f"set rulebase security rules {name_token(name)}"
    proto = spec.proto
    service = objects.service(proto, spec.sport, spec.dport) if proto in (6, 17) else ANY
    applications = objects.applications(proto, spec.icmp_types)
    lines = [
        f"{head} from {spec.from_zone}",
        f"{head} to {spec.to_zone}",
        f"{head} source {objects.address(spec.src)}",
        f"{head} destination {objects.address(spec.dst)}",
        f"{head} application {name_list(applications)}",
        f"{head} service {service}",
        f"{head} action {'allow' if spec.action == Action.permit else 'deny'}",
    ]
    if spec.log_start:
        lines.append(f"{head} log-start yes")
    if spec.action == Action.permit or spec.log_start:
        lines.append(f"{head} {_LOG_END}")
    if spec.disabled:
        lines.append(f"{head} disabled yes")
    if spec.remark:
        lines.append(f"{head} description {_quote_text(spec.remark)}")
    if spec.tags:
        lines.append(f"{head} tag {name_list(list(spec.tags))}")
    return lines


def emit_panos(policy: Policy) -> PanosEmission:
    """Emit the PAN-OS candidate config for ``policy``."""
    zones = ZoneMap.build(policy)
    env = BuildEnv(
        policy,
        zones,
        build_route_table(policy),
        device_addresses(policy),
        NatModel(policy),
        nat_control=policy.dialect == Dialect.pix or policy.nat_control,
    )
    specs: list[RuleSpec] = []
    for ctx in build_contexts(policy):
        specs += context_specs(env, ctx)
    specs.append(final_deny_spec())
    plan = plan_management(env)
    env.ledger += to_the_box_entries(env, plan)

    objects = ObjectTable(policy.name_aliases)
    names = NameRegistry()
    rule_lines: list[str] = []
    sources: dict[str, str] = {}
    for spec in specs:
        name = names.name(spec.key)
        sources[name] = spec.source
        rule_lines += _rule_lines(name, spec, objects)

    nat = nat_lines(env, objects)
    lines = [
        *network_lines(policy, zones),
        *_tag_lines(specs),
        *objects.address_lines(),
        *objects.group_lines(),
        *objects.service_lines(),
        *objects.application_lines(),
        *profile_lines(env, plan),
        *nat,
        *rule_lines,
    ]
    return PanosEmission(
        lines, zones, sources, env.unsupported, env.notes, number_entries(env.ledger)
    )
