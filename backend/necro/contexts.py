"""Policy contexts: one ingress interface's inbound policy, named ``<interface>:in``.

Contexts are what ``evaluate.decide`` is called with, and what the oracle enumerates, including
interfaces that have no ACL bound (their implicit behaviour has to be proven too).
For PIX/ASA the interface is the ``nameif``; for IOS it is the hardware name, because that is how
the golden flows and operators address it (the zone name is ``Interface.nameif``).
"""

from __future__ import annotations

from necro.ir import Context, Dialect, Policy


def build_contexts(policy: Policy) -> list[Context]:
    """One inbound context per interface, in interface order."""
    ios = policy.dialect == Dialect.ios
    global_acl = next((b.acl_name for b in policy.bindings if b.global_acl), "")
    contexts: list[Context] = []
    for iface in policy.interfaces:
        inbound = next(
            (
                b.acl_name
                for b in policy.bindings
                if b.direction == "in" and not b.global_acl and b.interface == iface.nameif
            ),
            "",
        )
        key = iface.hw_name if ios else iface.nameif
        contexts.append(
            Context(
                name=f"{key}:in",
                interface=key,
                acl_name=inbound,
                global_acl_name="" if ios else global_acl,
                address_space=policy.address_space,
            )
        )
    return contexts


def find_context(policy: Policy, name: str) -> Context:
    """The context called ``name`` (for example ``outside:in``). Raises KeyError if absent."""
    for ctx in build_contexts(policy):
        if ctx.name == name:
            return ctx
    raise KeyError(name)
