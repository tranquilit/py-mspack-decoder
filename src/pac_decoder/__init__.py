"""Pure-Python, dependency-free Microsoft Privilege Attribute Certificate decoding.

Security contract:
* ``decode_pac`` is a parser and does NOT authenticate PACs or signatures.
* For authorization, use ``decode_completed_context`` after GSSAPI has verified
  the PAC name attribute, or otherwise establish the trust of the raw bytes.
* The default strict mode rejects ambiguous or malformed recognized buffers,
  rather than returning an incomplete authorization identity.
* ``strict=False`` is for offline diagnostics ONLY, never authorization.
"""
from .binary import (
    PACDecodeError, decode_attributes_info, decode_client_info,
    decode_sid, decode_signature_type, decode_upn_dns_info, parse_pac,
)
from .claims import decode_claims_info
from .logon import decode_device_info, decode_logon_info, decode_delegation_info

BUFFER_NAMES = {
    1: "logon_info", 2: "credential_info", 6: "server_checksum",
    7: "kdc_checksum", 10: "client_info", 11: "constrained_delegation",
    12: "upn_dns_info", 13: "client_claims_info", 14: "device_info",
    15: "device_claims_info", 16: "ticket_checksum", 17: "attributes_info",
    18: "requestor_sid", 19: "full_checksum",
}
SIG_NAMES = {6: "server", 7: "kdc", 16: "ticket", 19: "full"}
# [MS-PAC] 2.4 explicitly requires recipients to ignore additional instances
# of these known buffer types. PAC_REQUESTOR_SID (18) is deliberately omitted:
# the published type entry requires one but does not specify how to handle
# additional instances. Do not silently choose between different requestors.
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3341cfa2-6ef5-42e0-b7bc-4544884bf399
_IGNORABLE_DUPLICATE_TYPES = frozenset({
    1, 2, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 19,
})
_EMPTY = (
    "sid", "sam_name", "upn", "dns_domain", "upn_dns_flags", "upn_constructed",
    "rid", "domain_sid", "domain_name", "logon_server", "full_name",
    "groups", "primary_group_rid", "extra_sids", "resource_groups",
    "group_count", "account_flags", "user_flags", "sub_auth_status",
    "last_logon", "last_successful_logon", "last_failed_logon",
    "logoff_time", "kickoff_time", "password_last_set",
    "password_can_change", "password_must_change", "logon_count",
    "bad_password_count", "failed_logon_count", "home_directory",
    "home_drive", "logon_script", "profile_path", "client_name",
    "client_auth_time", "requestor_sid", "pac_requested",
    "pac_given_implicitly", "pac_attributes_flags", "delegation_proxy_target",
    "delegation_transited_services", "device_info", "client_claims_present",
    "device_claims_present", "client_claims", "device_claims",
    "credential_info_present", "pac_signature_types", "pac_version",
    "pac_size", "pac_buffer_types", "pac_buffer_type_ids",
)


def empty_pac_info() -> dict:
    return dict.fromkeys(_EMPTY)


def _same_name(left: str | None, right: str | None) -> bool:
    """SAM account names are case-insensitive; UPNs are separate identifiers."""
    return left is None or right is None or left.casefold() == right.casefold()


def _same_upn_info(left: dict, right: dict) -> bool:
    """Do not silently prefer a separately supplied GSS attribute over the PAC."""
    for key in ("sid", "sam_name", "upn", "dns_domain"):
        a, b = left.get(key), right.get(key)
        if isinstance(a, str) and isinstance(b, str):
            if a.casefold() != b.casefold():
                return False
        elif a != b:
            return False
    return left["upn_dns_flags"] == right["upn_dns_flags"]


def decode_pac(raw_pac: bytes, upn_dns_attribute: bytes | None = None,
               *, errors: list[int] | None = None, strict: bool = True,
               require_logon: bool = False,
               ignore_invalid_claims: bool = False) -> dict:
    """Decode a raw MS-PAC as a dictionary; **does not authenticate it**.
    In strict mode (default), malformed recognized buffers, conflicting
    identity buffers, and missing/invalid LOGON_INFO (when
    ``require_logon=True``) raise PACDecodeError. For buffer types that MS-PAC
    2.4 explicitly says may be duplicated, only the FIRST occurrence is
    interpreted; later ones are ignored. Duplicate PAC_REQUESTOR_SID buffers
    remain an error because MS-PAC does not specify an ignore rule for them.
    Unknown buffer types are retained as metadata, not interpreted.
    No partial result is returned.
    ``strict=False`` is ONLY for offline diagnostics. In this mode malformed
    buffers are skipped and their type IDs are recorded in ``errors``. Its
    output MUST NOT be used for authorization. This is intentionally explicit
    to preserve the older diagnostic API while making normal use fail closed.
    ``upn_dns_attribute`` may ONLY come from an *independently authenticated*
    and complete GSSAPI name attribute. The library can't establish trust
    when caller-provided bytes are passed directly to this function.

    ``ignore_invalid_claims=True`` is an explicit compatibility mode: only
    malformed optional client/device claims (types 13 and 15) are skipped,
    never identity, logon, group, or other buffers. Missing claims must not
    be treated as successful claims-based authorization.
    """
    if (type(strict) is not bool or type(require_logon) is not bool
            or type(ignore_invalid_claims) is not bool):
        raise TypeError("strict, require_logon and ignore_invalid_claims must be booleans")
    pac = parse_pac(raw_pac)
    info = empty_pac_info()
    info["pac_size"] = pac.size
    info["pac_version"] = pac.version
    info["pac_buffer_type_ids"] = [buf.type_id for buf in pac.buffers]
    info["pac_buffer_types"] = [
        BUFFER_NAMES.get(buf.type_id, f"unknown_{buf.type_id}")
        for buf in pac.buffers
    ]
    present = set(info["pac_buffer_type_ids"])
    info["client_claims_present"] = 13 in present
    info["device_claims_present"] = 15 in present
    info["credential_info_present"] = 2 in present
    info["pac_signature_types"] = {}

    seen = set()
    buffers = {}
    for buf in pac.buffers:
        if buf.type_id in seen:
            # The first occurrence always wins; an invalid FIRST occurrence
            # must still fail strict parsing (never fall back to a later one).
            # parse_pac() already validated the directory spans of ALL buffers.
            if (strict and buf.type_id in BUFFER_NAMES
                    and buf.type_id not in _IGNORABLE_DUPLICATE_TYPES):
                raise PACDecodeError(
                    f"duplicate PAC buffer without defined ignore semantics: "
                    f"{BUFFER_NAMES[buf.type_id]} ({buf.type_id})"
                )
            continue
        seen.add(buf.type_id)
        buffers[buf.type_id] = buf.data

    # Decode BOTH versions of UPN_DNS_INFO, if present. Do not allow a
    # separately authenticated attribute to overwrite identity silently.
    inline = buffers.get(12)
    try:
        if inline is not None:
            info.update(decode_upn_dns_info(inline))
        if upn_dns_attribute is not None:
            separate = decode_upn_dns_info(upn_dns_attribute)
            if inline is not None and not _same_upn_info(info, separate):
                raise PACDecodeError("conflicting PAC and GSSAPI UPN_DNS_INFO")
            if inline is None:
                info.update(separate)
    except PACDecodeError as exc:
        if strict:
            raise PACDecodeError(f"invalid PAC UPN_DNS_INFO: {exc}") from exc
        if errors is not None:
            errors.append(12)
        # Do not expose even the original UPN fields on an inconsistent parse.
        for key in ("sid", "sam_name", "upn", "dns_domain", "upn_dns_flags", "upn_constructed"):
            info[key] = None

    for t, data in buffers.items():
        if t == 12:
            continue
        try:
            if t == 1:
                logon = decode_logon_info(data)
                if not logon.get("sid") or not isinstance(logon.get("groups"), list):
                    raise PACDecodeError("LOGON_INFO missing account SID or group list")
                if info["sid"] is not None and info["sid"] != logon["sid"]:
                    raise PACDecodeError("conflicting account SIDs in PAC identity buffers")
                if not _same_name(info["sam_name"], logon["sam_name"]):
                    raise PACDecodeError("conflicting SAM account names in PAC identity buffers")
                upn_sam = info["sam_name"]
                info.update(logon)
                if upn_sam is not None:
                    info["sam_name"] = upn_sam
            elif t == 10:
                info.update(decode_client_info(data))
            elif t == 11:
                info.update(decode_delegation_info(data))
            elif t == 14:
                info["device_info"] = decode_device_info(data)
            elif t == 17:
                info.update(decode_attributes_info(data))
            elif t == 18:
                info["requestor_sid"] = decode_sid(data)
            elif t in SIG_NAMES:
                info["pac_signature_types"][SIG_NAMES[t]] = decode_signature_type(data)
            elif t in (13, 15):
                key = "client_claims" if t == 13 else "device_claims"
                # Samba and Windows may include a zero-length claims buffer
                # when there are no claims. There is no NDR envelope to parse.
                # Keep *_claims_present=True and decoded claims=None.
                if data:
                    info[key] = decode_claims_info(data)
        except PACDecodeError as exc:
            if strict and not (ignore_invalid_claims and t in (13, 15)):
                raise PACDecodeError(
                    f"invalid PAC {BUFFER_NAMES.get(t, f'buffer {t}')} ({t}): {exc}"
                ) from exc
            if errors is not None:
                errors.append(t)
            # In diagnostic mode, never leak authorization identity from an
            # invalid LOGON_INFO (even if UPN_DNS_INFO was decoded earlier).
            if t == 1:
                for field in ("groups", "extra_sids", "resource_groups", "group_count"):
                    info[field] = None
    if require_logon and (1 not in buffers or info["sid"] is None or info["groups"] is None):
        raise PACDecodeError("valid PAC LOGON_INFO required")
    return info


__all__ = [
    "PACDecodeError", "parse_pac", "decode_sid", "decode_upn_dns_info",
    "decode_logon_info", "decode_device_info", "decode_delegation_info",
    "decode_pac", "empty_pac_info", "decode_claims_info",
]
