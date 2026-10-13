"""Read an authenticated MS-PAC from a completed Kerberos GSSAPI acceptor.

This module does not import python-gssapi at import time. GSSAPI performs the
PAC verification; this parser must never be given unchecked attributes.
"""
from __future__ import annotations

from . import PACDecodeError, decode_pac
from .binary import MAX_PAC_BYTES

_KERBEROS_MECH = "1.2.840.113554.1.2.2"


class PACAttributeError(PACDecodeError):
    """An acceptor context has no usable, authenticated PAC name attribute."""


def _attribute_value(name: object, key: str, *, required: bool) -> bytes | None:
    """Extract a *single* authenticated, complete RFC 6680 name attribute."""
    try:
        attributes = name.attributes
        if attributes is None:
            raise PACAttributeError("GSSAPI name attributes are unavailable")
        # The public Name.attributes mapping may raise a native GSSAPI error
        # rather than KeyError when fetching a missing attribute. Enumerate
        # first so the absence of an optional attribute is unambiguous.
        keys = list(attributes.keys())
        if key in keys:
            lookup_key = key
        elif key.encode("ascii") in keys:
            lookup_key = key.encode("ascii")
        else:
            if required:
                raise PACAttributeError(f"missing GSSAPI name attribute: {key}")
            return None
        attribute = attributes[lookup_key]
    except PACAttributeError:
        raise
    except Exception as exc:
        raise PACAttributeError(f"unable to obtain GSSAPI name attribute: {key}") from exc
    if not getattr(attribute, "authenticated", False):
        raise PACAttributeError(f"unauthenticated GSSAPI name attribute: {key}")
    if not getattr(attribute, "complete", False):
        raise PACAttributeError(f"incomplete GSSAPI name attribute: {key}")
    try:
        values = list(attribute.values)
    except (AttributeError, TypeError) as exc:
        raise PACAttributeError(f"invalid GSSAPI name attribute values: {key}") from exc
    if len(values) != 1 or type(values[0]) is not bytes:
        raise PACAttributeError(f"expected exactly one binary GSSAPI attribute: {key}")
    if not 0 < len(values[0]) <= MAX_PAC_BYTES:
        raise PACAttributeError(f"invalid GSSAPI name attribute size: {key}")
    return values[0]

def decode_completed_context(context: object, *, errors: list[int] | None = None,
                             require_logon: bool = True,
                             ignore_invalid_claims: bool = False,
                             include_resource_groups: bool = True) -> dict:
    """Decode the PAC of a completed **Kerberos acceptor** context.
    Rejects incomplete contexts, non-Kerberos mechanisms, unauthenticated or
    incomplete PAC attributes and malformed or ambiguous PAC structures.
    ``require_logon=True`` ensures the identity and group set are complete.
    No PAC cryptography is implemented in this package; the verification is
    delegated to the underlying GSSAPI / Kerberos implementation.

    ``ignore_invalid_claims`` can preserve valid identity and groups when an
    optional client/device claims buffer is malformed. Never authorize based
    on claims whose decoded value is None.
    ``include_resource_groups=False`` excludes only PAC_LOGON_INFO
    resource groups from top-level authorization lists. Device groups
    and ExtraSids are unaffected.
    """
    if not getattr(context, "complete", False):
        raise PACAttributeError("GSSAPI security context is not complete")
    if getattr(context, "locally_initiated", None) is not False:
        raise PACAttributeError("expected a GSSAPI acceptor, not initiator")
    try:
        mechanism = context.mech
    except Exception as exc:
        raise PACAttributeError("unable to determine negotiated GSSAPI mechanism") from exc
    if getattr(mechanism, "dotted_form", None) != _KERBEROS_MECH:
        raise PACAttributeError("GSSAPI mechanism is not Kerberos")
    try:
        name = context.initiator_name
    except Exception as exc:
        raise PACAttributeError("GSSAPI initiator name is unavailable") from exc
    if name is None:
        raise PACAttributeError("GSSAPI initiator name is unavailable")
    pac = _attribute_value(name, "urn:mspac:", required=True)
    upn = _attribute_value(name, "urn:mspac:upn-dns-info", required=False)
    return decode_pac(pac, upn_dns_attribute=upn,
                      errors=errors, strict=True, require_logon=require_logon,
                      ignore_invalid_claims=ignore_invalid_claims,
                      include_resource_groups=include_resource_groups)


__all__ = ["PACAttributeError", "decode_completed_context"]
