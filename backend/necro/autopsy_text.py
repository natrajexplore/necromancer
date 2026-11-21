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
}


def render(kind: str, **details: str) -> tuple[str, str, str]:
    """(label, explanation, recommendation) for ``kind``, filled in with ``details``."""
    label, explanation, recommendation = TEMPLATES[kind]
    return label, explanation.format(**details), recommendation.format(**details)
