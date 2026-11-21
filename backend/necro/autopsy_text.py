"""Plain-English wording for autopsy findings: themed label, explanation, recommendation.

The label is the only themed part (the UI shows it). Explanations and recommendations are plain
and professional, because they end up in the report. Templates use ``str.format`` with
``rule_ref`` and the per-finding details passed to ``render``.
"""

from __future__ import annotations

# kind -> (themed label, explanation template, recommendation template)
TEMPLATES: dict[str, tuple[str, str, str]] = {
    "shadowed": (
        "Buried Rule",
        "{rule_ref} can never match: every flow it describes is already handled by {by}, "
        "which come earlier in the list.",
        "Remove {rule_ref}, or move it above the rule(s) that shadow it if it was meant to apply. "
        "Check with the rule owner first: it may record an intent that was never enforced.",
    ),
    "redundant": (
        "Echo of a Rule",
        "{rule_ref} adds nothing: every flow that reaches it is {verb} by {by}, which come "
        "later with the same action and with no conflicting rule in between.",
        "Remove {rule_ref} after the owner confirms. Removing it changes no decision.",
    ),
    "overly-broad": (
        "Open Grave",
        "{rule_ref} permits {scope}. Traffic from {zone} is allowed to reach any destination "
        "without being limited to the services a business owner approved.",
        "Replace {rule_ref} with rules for the specific sources, destinations and services that "
        "are needed. Use the zero-trust tightening output as a starting point, and keep this "
        "rule until the replacements are proven.",
    ),
    "insecure-service": (
        "Cursed Port",
        "{rule_ref} permits {services} from {zone}. These services send credentials or data in "
        "clear text or have a long history of abuse.",
        "Confirm the business need with the rule owner. Replace {services} with an encrypted "
        "alternative (SSH, SFTP, SNMPv3, HTTPS) or restrict the rule to the smallest set of "
        "source addresses, and record an expiry for any accepted risk.",
    ),
    "unused-object": (
        "Orphaned Relic",
        "Object-group {name} is defined but no rule refers to it, directly or through another "
        "group.",
        "Delete {name} after confirming it is not referenced outside this configuration "
        "(for example by a VPN or monitoring tool).",
    ),
    "unused-acl": (
        "Abandoned Crypt",
        "Access list {name} is not bound to any interface and nothing else refers to it.",
        "Delete {name} after confirming nothing outside this configuration depends on it.",
    ),
    "insecure-management": (
        "Unlocked Crypt Door",
        "{what}",
        "{advice}",
    ),
    "unfiltered-interface": (
        "Unguarded Gate",
        "Interface {name} has no access list bound to inbound traffic. {behaviour}",
        "Bind an explicit access list to {name} that permits only the traffic that is needed, "
        "ending with a logged deny, so the behaviour does not depend on defaults.",
    ),
    "return-traffic": (
        "Lingering Spirit",
        "{rule_ref} {why}. A stateful firewall tracks sessions, so the rule is not needed there "
        "and it also permits packets that are not part of any session.",
        "Keep {rule_ref} for the like-for-like migration, then remove it in a separate "
        "tightening change once session tracking is in place and proven.",
    ),
    "no-remark": (
        "Nameless Tomb",
        "{rule_ref} has no remark, so there is no recorded business reason for it.",
        "Ask the rule owner for the purpose and add it as a remark (it becomes the rule "
        "description on the target platform).",
    ),
}


def render(kind: str, **details: str) -> tuple[str, str, str]:
    """(label, explanation, recommendation) for ``kind``, filled in with ``details``."""
    label, explanation, recommendation = TEMPLATES[kind]
    return label, explanation.format(**details), recommendation.format(**details)
