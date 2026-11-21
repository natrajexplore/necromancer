"""Address-space rules for pre-8.3 sources (policy-semantics 1.5, requirement 4.11).

PIX 6.x and ASA <= 8.2 write ACLs in *mapped* (global) addresses. PAN-OS security rules match the
pre-NAT destination address, which is the mapped address, so the ACL address is kept as written.
The rule's destination *zone* is the post-NAT zone: the route lookup of the real address.

PIX 6.x always enforces nat-control, and an ASA does when ``nat-control`` is configured: a flow
with no translation is dropped even if an ACL permits it. PAN-OS has no such check, so permit rules
are narrowed to the flows the source device translates, using the same translation space that
``NatModel.translates`` consults.
"""

from __future__ import annotations

from necro.boxes import Box
from necro.emitters.panos_env import ANY_ZONE, BuildEnv
from necro.ir import AddressSpace
from necro.sets import AddrSet

_SRC, _DST = 0, 1


def _mapped_partition(env: BuildEnv, ingress: str, dst: AddrSet) -> list[tuple[str, AddrSet]]:
    """Egress interface per part of ``dst``, looking up real addresses for statics (nameif)."""
    split = env.nat.split_mapped(ingress, dst)
    parts: list[tuple[str, AddrSet]] = []
    for _mapped, real, offset in split.translated:
        for nameif, real_part in env.routes.partition(real):
            back = AddrSet([(iv.lo - offset, iv.hi - offset) for iv in real_part.intervals])
            parts.append((nameif, back))
    if not split.port_dependent.is_empty():
        parts.append((ANY_ZONE, split.port_dependent))  # the real address depends on proto/port
    return parts + env.routes.partition(split.untouched)


def zone_pieces(env: BuildEnv, dst: AddrSet, ingress: str | None) -> list[tuple[str, AddrSet]]:
    """Split a destination set by egress zone, in interface order, unrouted space last.

    ``ingress`` is the nameif the rule is evaluated on (None for IOS). A destination of ``any``
    spans every zone, so it stays one piece with the zone ``any``.
    """
    if dst == AddrSet.any():
        return [(ANY_ZONE, dst)]
    mapped = ingress is not None and env.policy.address_space == AddressSpace.mapped
    if mapped and ingress is not None:
        parts = _mapped_partition(env, ingress, dst)
    else:
        parts = env.routes.partition(dst)
    merged: dict[str, AddrSet] = {}
    for nameif, part in parts:
        zone = env.zones.of_nameif(nameif)
        merged[zone] = merged[zone].union(part) if zone in merged else part
    order = {zone: index for index, zone in enumerate(env.zones.order)}
    return sorted(merged.items(), key=lambda piece: order.get(piece[0], len(order)))


def translated_pieces(
    env: BuildEnv, ingress: str | None, src: AddrSet, dst: AddrSet
) -> list[tuple[AddrSet, AddrSet]]:
    """The (source, destination) parts of a permit that the source device would translate.

    Translated means the source is in the translation space's sources, or the destination is in
    its destinations; the two parts are disjoint. Without nat-control the match is unchanged.
    """
    if not env.nat_control or ingress is None:
        return [(src, dst)]
    sources, destinations = env.nat.translation_space(ingress)
    candidates = [
        (src.intersect(sources), dst),
        (src.subtract(sources), dst.intersect(destinations)),
    ]
    return [(s, d) for s, d in candidates if not s.is_empty() and not d.is_empty()]


def restrict_translated(env: BuildEnv, ingress: str | None, boxes: list[Box]) -> list[Box]:
    """``boxes`` narrowed to the flows the source device translates (nat-control)."""
    if not env.nat_control or ingress is None:
        return boxes
    sources, destinations = env.nat.translation_space(ingress)
    narrowed: list[Box] = []
    for box in boxes:
        src = box.dims[_SRC]
        assert isinstance(src, AddrSet)
        by_source = box.restrict(_SRC, sources)
        by_destination = box.restrict(_SRC, src.subtract(sources))
        if by_destination is not None:
            by_destination = by_destination.restrict(_DST, destinations)
        narrowed += [b for b in (by_source, by_destination) if b is not None]
    return narrowed
