# -*- coding: utf-8 -*-
"""
TLS/SSL checks using SSLyze 6.2.0 + helper libs.

Implements the checklist requested:
1) Validity/expiry
2) Issuer & chain of trust
3) Domain/SAN match
4) Key length & algorithm; weak sig algs
5) Wildcard/multi-domain coverage
6) Supported TLS versions
7) Forward secrecy (PFS)
8) Cipher strength (allow strong only)
9) Cipher preference order (best-effort)
10) Known vulns: Heartbleed, POODLE, BEAST, CRIME, ROBOT, DROWN
11) Renegotiation (secure/insecure)
12) Compression (CRIME)
13) OCSP stapling
14) HSTS
15) Certificate Transparency (SCT)
16) Session resumption
17) DNS CAA
18) PFS (reported alongside #7)

Notes:
- Built for SSLyze 6.2.0 Python API (`ServerNetworkLocation`, `Scanner.queue_scans`,
  `get_results`, and `ScanCommandAttemptStatusEnum`).
- HSTS via ScanCommand.HTTP_HEADERS (parsed header), not via `requests`.
- OCSP stapling via CertificateInfo results (`ocsp_response`).
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

import idna
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtensionOID, NameOID

# SSLyze 6.2.0 API
from sslyze import (
    ServerNetworkLocation,
    Scanner,
    ServerScanRequest,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
)

import json
import sys

__all__ = ["run_ssl_checks", "CheckResult"]

# ---------- Result helpers ----------

@dataclass
class CheckResult:
    status: str  # PASS | WARN | FAIL | INFO | NA | ERROR
    summary: str
    details: Optional[dict] = None


def _pass(msg, **details) -> CheckResult:
    return CheckResult("PASS", msg, details or None)


def _warn(msg, **details) -> CheckResult:
    return CheckResult("WARN", msg, details or None)


def _fail(msg, **details) -> CheckResult:
    return CheckResult("FAIL", msg, details or None)


def _info(msg, **details) -> CheckResult:
    return CheckResult("INFO", msg, details or None)


def _error(msg, **details) -> CheckResult:
    return CheckResult("ERROR", msg, details or None)


# ---------- Helpers ----------

def _names_from_cert(cert: x509.Certificate) -> Tuple[List[str], Optional[str]]:
    san: List[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san = [idna.decode(x) for x in san_ext.get_values_for_type(x509.DNSName)]
    except Exception:
        pass
    cn = None
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            cn = cn_attrs[0].value
    except Exception:
        pass
    return san, cn


def _host_matches_cert(hostname: str, san: List[str], cn: Optional[str]) -> bool:
    host = hostname.lower()

    def _match(pattern: str) -> bool:
        p = pattern.lower()
        if p.startswith("*."):
            # Strict-ish wildcard: must match at least one subdomain, depth-aware
            return (host == p[2:]) or (host.endswith(p[1:]) and host.count(".") >= p.count("."))
        return host == p

    for name in san:
        if _match(name):
            return True
    return _match(cn) if cn else False


def _sig_alg_weak(cert: x509.Certificate) -> Tuple[bool, str]:
    """Flags MD5/SHA-1 via parsed hash; works across cryptography versions."""
    try:
        name = getattr(cert.signature_hash_algorithm, "name", None)
    except Exception:
        name = None
    if not name:
        return False, "unknown"
    if name.lower() in {"md5", "sha1"}:
        return True, name.upper()
    return False, name.upper()


def _key_info(cert: x509.Certificate) -> Tuple[str, int, Optional[str]]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size, None
    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve = getattr(pub.curve, "name", str(pub.curve))
        size = getattr(pub, "key_size", 0)
        return "ECDSA", size, curve
    # Fallback
    return pub.__class__.__name__, 0, None


def _attempt_ok(attempt) -> Optional[object]:
    if attempt and attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
        return attempt.result
    return None


def _version_enabled(cipher_result) -> bool:
    try:
        return bool(cipher_result and cipher_result.accepted_cipher_suites)
    except Exception:
        return False


def _cipher_names(cipher_result) -> List[str]:
    try:
        return [cs.cipher_suite.name for cs in cipher_result.accepted_cipher_suites]
    except Exception:
        return []


def _has_pfs(cipher_result) -> bool:
    try:
        # TLS 1.3 is always PFS by design; TLS 1.2 suites with (EC)DHE have ephemeral_key
        names = _cipher_names(cipher_result)
        if getattr(cipher_result, "tls_version_used", None) and str(cipher_result.tls_version_used).endswith("TLS_1_3"):
            return True
        return any(("ECDHE" in n) or ("DHE" in n) for n in names)
    except Exception:
        return False


def _has_weak_cipher(cipher_names: List[str]) -> Tuple[bool, List[str]]:
    WEAK = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "IDEA", "SEED")
    found = [n for n in cipher_names if any(w in n for w in WEAK)]
    return (len(found) > 0), found


def _has_strong_cipher(cipher_names: List[str]) -> bool:
    return any(("AES_128_GCM" in n) or ("AES_256_GCM" in n) or ("CHACHA20_POLY1305" in n) for n in cipher_names)


def _dns_caa(hostname: str) -> Tuple[bool, List[str]]:
    labels = hostname.strip(".").split(".")
    records: List[str] = []
    for i in range(len(labels) - 1):
        zone = ".".join(labels[i:])
        try:
            ans = dns.resolver.resolve(zone, "CAA")
            for rr in ans:
                records.append(rr.to_text())
            if records:
                return True, records
        except Exception:
            continue
    return False, records


# ---------- Main entry ----------

def run_ssl_checks(hostname: str, port: int = 443, deadline_days_min: int = 30) -> Dict[str, Dict[str, CheckResult]]:
    """Run all checks against `hostname:port` and return a nested dict of CheckResult.

    Return shape:
    {
      'certificate': {k: CheckResult_dict, ...},
      'protocols': {...},
      'ciphers': {...},
      'vulnerabilities': {...},
      'best_practices': {...}
    }
    """
    hn = idna.encode(hostname).decode()

    # --- Build & run the scan with SSLyze ---
    scan_commands = {
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.HEARTBLEED,
        ScanCommand.TLS_COMPRESSION,
        ScanCommand.ROBOT,
        ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.SESSION_RESUMPTION,
        ScanCommand.HTTP_HEADERS,
        # ScanCommand.ELLIPTIC_CURVES,  # not strictly required for PFS check
        # ScanCommand.TLS_EXTENDED_MASTER_SECRET,
    }

    server_loc = ServerNetworkLocation(hostname=hn, port=port)
    scanner = Scanner()
    req = ServerScanRequest(server_location=server_loc, scan_commands=list(scan_commands))
    scanner.queue_scans([req])
    server_scan_result = next(scanner.get_results())  # single target

    if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
        raise RuntimeError(
            f"Could not connect to {hostname}:{port}: {server_scan_result.connectivity_error_trace}"
        )

    attempts = server_scan_result.scan_result  # AllScanCommandsAttempts

    # Extract per-command results (None if not completed)
    tls13 = _attempt_ok(attempts.tls_1_3_cipher_suites)
    tls12 = _attempt_ok(attempts.tls_1_2_cipher_suites)
    tls11 = _attempt_ok(attempts.tls_1_1_cipher_suites)
    tls10 = _attempt_ok(attempts.tls_1_0_cipher_suites)
    ssl3 = _attempt_ok(attempts.ssl_3_0_cipher_suites)
    ssl2 = _attempt_ok(attempts.ssl_2_0_cipher_suites)
    ci = _attempt_ok(attempts.certificate_info)
    hb = _attempt_ok(attempts.heartbleed)
    comp = _attempt_ok(attempts.tls_compression)
    robot = _attempt_ok(attempts.robot)
    reneg = _attempt_ok(attempts.session_renegotiation)
    resumption = _attempt_ok(attempts.session_resumption)
    http_headers = _attempt_ok(attempts.http_headers)

    # ---------- Certificate checks ----------
    cert: Dict[str, CheckResult] = {}

    # Choose a certificate deployment (prefer the first with a verified path)
    leaf: Optional[x509.Certificate] = None
    deployment = None
    if ci:
        deployments = list(getattr(ci, "certificate_deployments", []) or [])
        # Prefer a deployment with any successful path validation
        for d in deployments:
            for pvr in getattr(d, "path_validation_results", []) or []:
                if getattr(pvr, "was_validation_successful", False):
                    deployment = d
                    break
            if deployment:
                break
        if deployment is None and deployments:
            deployment = deployments[0]
        if deployment is not None:
            try:
                leaf = deployment.received_certificate_chain[0]
            except Exception:
                leaf = None

    # 1) Validity / Expiry
    if leaf:
        now = _dt.datetime.utcnow()
        not_before = leaf.not_valid_before.replace(tzinfo=None)
        not_after = leaf.not_valid_after.replace(tzinfo=None)
        days_left = (not_after - now).days
        if now < not_before or now >= not_after:
            cert["validity_expiry"] = _fail(
                "Certificate is expired or not yet valid",
                not_before=str(not_before),
                not_after=str(not_after),
            )
        elif days_left < deadline_days_min:
            cert["validity_expiry"] = _warn(
                f"Certificate expires soon ({days_left} days remaining)",
                not_after=str(not_after),
            )
        else:
            cert["validity_expiry"] = _pass(
                f"Valid until {not_after.date()} ({days_left} days left)"
            )
    else:
        cert["validity_expiry"] = _error("Could not read leaf certificate from server response")

    # 2) Issuer & Chain of Trust (+ intermediate install)
    try:
        verified = False
        errors: List[str] = []
        order_ok = None
        contains_anchor = None
        if deployment is not None:
            order_ok = getattr(deployment, "received_chain_has_valid_order", None)
            contains_anchor = getattr(deployment, "received_chain_contains_anchor_certificate", None)
            for pvr in getattr(deployment, "path_validation_results", []) or []:
                if getattr(pvr, "was_validation_successful", False):
                    verified = True
                else:
                    err = getattr(pvr, "validation_error", None)
                    if err:
                        errors.append(str(err))
        if verified:
            cert["issuer_chain"] = _pass(
                "Chain validates to a trusted root",
                received_chain_has_valid_order=order_ok,
                received_chain_contains_anchor=contains_anchor,
            )
        else:
            cert["issuer_chain"] = _fail(
                "Chain does not validate to a trusted root",
                issues=errors or None,
                received_chain_has_valid_order=order_ok,
                received_chain_contains_anchor=contains_anchor,
            )
    except Exception as e:
        cert["issuer_chain"] = _error("Chain validation check failed", error=str(e))

    # 3) Domain/SAN match
    if leaf:
        san, cn = _names_from_cert(leaf)
        matches = _host_matches_cert(hn, san, cn)
        cert["domain_san"] = (
            _pass("Hostname matches certificate SAN/CN", san=san, cn=cn)
            if matches
            else _fail("Hostname does not match certificate", san=san, cn=cn)
        )
    else:
        cert["domain_san"] = _error("No certificate available for SAN match")

    # 4) Key length & algorithm + weak signature
    if leaf:
        ktype, kbits, curve = _key_info(leaf)
        weak_sig, sig_name = _sig_alg_weak(leaf)
        if (ktype == "RSA" and kbits < 2048) or (ktype == "ECDSA" and not curve):
            cert["key_algo"] = _fail("Weak key parameters", type=ktype, bits=kbits, curve=curve)
        else:
            cert["key_algo"] = _pass("Key parameters are strong", type=ktype, bits=kbits, curve=curve)
        cert["sig_alg"] = _fail(f"Weak signature algorithm ({sig_name})") if weak_sig else _pass(
            f"Signature algorithm: {sig_name}"
        )
    else:
        cert["key_algo"] = _error("No certificate available for key check")
        cert["sig_alg"] = _error("No certificate available for signature check")

    # 5) Wildcard / multi-domain coverage (informational)
    if leaf:
        san, _ = _names_from_cert(leaf)
        wildcard = any(s.startswith("*.") for s in san)
        cert["wildcard_multi"] = _info(
            "Wildcard/multi-domain info",
            wildcard=wildcard,
            san_count=len(san),
            san=san,
        )
    else:
        cert["wildcard_multi"] = _error("No certificate available to evaluate SANs")

    # 13) OCSP stapling (from CertificateInfo)
    if deployment is not None:
        stapled = getattr(deployment, "ocsp_response", None) is not None
        ocsp_trusted = getattr(deployment, "ocsp_response_is_trusted", None)
        cert["ocsp_stapling"] = (
            _pass("OCSP stapling enabled", ocsp_trusted=ocsp_trusted)
            if stapled
            else _warn("OCSP stapling not enabled")
        )
    else:
        cert["ocsp_stapling"] = _info("OCSP status unknown (no deployment parsed)")

    # 15) Certificate Transparency (SCT)
    if deployment is not None:
        sct_count = getattr(deployment, "leaf_certificate_signed_certificate_timestamps_count", None)
        if isinstance(sct_count, int) and sct_count > 0:
            cert["certificate_transparency"] = _pass("Embedded SCT(s) present", count=sct_count)
        else:
            cert["certificate_transparency"] = _warn("No embedded SCT found")
    else:
        cert["certificate_transparency"] = _info("CT check skipped (no deployment)")

    # ---------- Protocols and ciphers ----------
    protocols: Dict[str, CheckResult] = {}
    ciphers: Dict[str, CheckResult] = {}

    enabled = {
        "TLS1.3": _version_enabled(tls13),
        "TLS1.2": _version_enabled(tls12),
        "TLS1.1": _version_enabled(tls11),
        "TLS1.0": _version_enabled(tls10),
        "SSL3": _version_enabled(ssl3),
        "SSL2": _version_enabled(ssl2),
    }

    # 6) Supported TLS versions policy
    if enabled["TLS1.3"] or enabled["TLS1.2"]:
        if any(enabled[v] for v in ("TLS1.1", "TLS1.0", "SSL3", "SSL2")):
            protocols["versions"] = _warn("Legacy protocols enabled", enabled=enabled)
        else:
            protocols["versions"] = _pass("Only TLS 1.2/1.3 enabled", enabled=enabled)
    else:
        protocols["versions"] = _fail("TLS 1.2/1.3 not enabled", enabled=enabled)

    # 7 & 18) Forward secrecy
    pfs_supported = False
    for r in (tls13, tls12):
        if _has_pfs(r):
            pfs_supported = True
            break
    protocols["pfs"] = _pass("Forward secrecy supported") if pfs_supported else _fail(
        "No forward secrecy (ECDHE/DHE)"
    )

    # 8) Cipher strength
    weak_any = False
    weak_list: List[str] = []
    strong_any = False
    for r in (tls13, tls12, tls11, tls10, ssl3, ssl2):
        if not r:
            continue
        names = _cipher_names(r)
        w, lst = _has_weak_cipher(names)
        weak_any = weak_any or w
        if lst:
            weak_list.extend(lst)
        strong_any = strong_any or _has_strong_cipher(names)
    if weak_any:
        ciphers["strength"] = _fail("Weak ciphers supported", weak=sorted(set(weak_list)))
    elif strong_any:
        ciphers["strength"] = _pass("Strong ciphers only (AES-GCM/ChaCha20)")
    else:
        ciphers["strength"] = _warn("Could not confirm strong ciphers")

    # 9) Cipher preference order (not exposed reliably in SSLyze 6.2.0)
    ciphers["server_order"] = _info("Cipher preference order not determined (API limitation)")

    # ---------- Vulnerabilities ----------
    vulns: Dict[str, CheckResult] = {}

    # 10) Heartbleed
    try:
        hb_flag = bool(hb and getattr(hb, "is_vulnerable_to_heartbleed", False))
        vulns["heartbleed"] = _fail("Vulnerable to Heartbleed") if hb_flag else _pass(
            "Not vulnerable to Heartbleed"
        )
    except Exception:
        vulns["heartbleed"] = _info("Heartbleed check inconclusive")

    # ROBOT
    try:
        if robot and getattr(robot, "robot_result", None):
            result_name = str(robot.robot_result)
            print(f"Result:{result_name}")

             # Enumerations are like RobotScanResultEnum.VULNERABLE_...
            if "NOT_VULNERABLE" in result_name:
                vulns["robot"] = _pass("Not vulnerable to ROBOT", result=result_name)
            elif "VULNERABLE" in result_name:
                vulns["robot"] = _fail("Vulnerable to ROBOT", result=result_name)
            else:
                vulns["robot"] = _info("ROBOT result inconclusive", result=result_name)
        else:
            vulns["robot"] = _info("ROBOT scan unavailable")
    except Exception:
        vulns["robot"] = _info("ROBOT check inconclusive")
 
    #         # Enumerations are like RobotScanResultEnum.VULNERABLE_...
    #         if "VULNERABLE" in result_name:
    #             vulns["robot"] = _fail("Vulnerable to ROBOT", result=result_name)
    #         elif "NOT_VULNERABLE" in result_name:
    #             vulns["robot"] = _pass("Not vulnerable to ROBOT", result=result_name)
    #         else:
    #             vulns["robot"] = _info("ROBOT result inconclusive", result=result_name)
    #     else:
    #         vulns["robot"] = _info("ROBOT scan unavailable")
    # except Exception:
    #     vulns["robot"] = _info("ROBOT check inconclusive")

    # POODLE: SSL 3.0 enabled
    vulns["poodle"] = _fail("SSL 3.0 enabled (POODLE risk)") if enabled["SSL3"] else _pass(
        "SSL 3.0 disabled"
    )

    # BEAST: TLS1.0 + CBC ciphers
    try:
        t10_names = _cipher_names(tls10) if tls10 else []
        beast = enabled["TLS1.0"] and any("CBC" in n and "GCM" not in n for n in t10_names)
        vulns["beast"] = _warn("TLS 1.0 with CBC ciphers (BEAST risk)") if beast else _pass(
            "No BEAST risk detected"
        )
    except Exception:
        vulns["beast"] = _info("BEAST check inconclusive")

    # CRIME: TLS compression
    try:
        supports_comp = bool(comp and getattr(comp, "supports_compression", False))
        vulns["crime"] = _fail("TLS compression enabled (CRIME)") if supports_comp else _pass(
            "TLS compression disabled"
        )
    except Exception:
        vulns["crime"] = _info("CRIME check inconclusive")

    # DROWN: SSLv2 on same endpoint
    vulns["drown"] = _fail("SSL 2.0 enabled (DROWN risk)") if enabled["SSL2"] else _pass(
        "SSL 2.0 disabled"
    )

    # 11) Renegotiation
    try:
        if reneg:
            secure = getattr(reneg, "supports_secure_renegotiation", False)
            client_reneg_dos = getattr(reneg, "is_vulnerable_to_client_renegotiation_dos", False)
            if client_reneg_dos:
                vulns["renegotiation"] = _fail("Client-initiated renegotiation DoS supported")
            elif secure:
                vulns["renegotiation"] = _pass("Secure renegotiation supported")
            else:
                vulns["renegotiation"] = _warn("Renegotiation disabled (usually fine)")
        else:
            vulns["renegotiation"] = _info("Renegotiation scan unavailable")
    except Exception:
        vulns["renegotiation"] = _info("Renegotiation check inconclusive")

    # 12) Compression echoed for completeness
    vulns["compression"] = vulns.get("crime", _info("Compression status unknown"))

    # ---------- Best practices ----------
    best: Dict[str, CheckResult] = {}

    # 14) HSTS via HTTP_HEADERS
    if http_headers and getattr(http_headers, "strict_transport_security_header", None):
        h = http_headers.strict_transport_security_header
        best["hsts"] = _pass(
            "HSTS header present",
            max_age=getattr(h, "max_age", None),
            preload=getattr(h, "preload", None),
            include_subdomains=getattr(h, "include_subdomains", None),
        )
    else:
        best["hsts"] = _warn("HSTS header not present")

    # 16) Session Resumption
    if resumption:
        # Enum values: FULLY_SUPPORTED, PARTIALLY_SUPPORTED, NOT_SUPPORTED, SERVER_IS_TLS_1_3_ONLY
        res_summary = str(getattr(resumption, "session_id_resumption_result", ""))
        ticket_summary = str(getattr(resumption, "tls_ticket_resumption_result", ""))
        # Prefer overall based on both mechanisms
        overall = (res_summary, ticket_summary)
        if any("FULLY_SUPPORTED" in x or "PARTIALLY_SUPPORTED" in x for x in overall):
            best["session_resumption"] = _pass(
                "Session resumption supported",
                session_id=res_summary,
                session_ticket=ticket_summary,
            )
        elif any("SERVER_IS_TLS_1_3_ONLY" in x for x in overall):
            best["session_resumption"] = _info(
                "Server is TLS 1.3 only (TLS 1.2 resumption N/A)",
                session_id=res_summary,
                session_ticket=ticket_summary,
            )
        else:
            best["session_resumption"] = _warn(
                "Session resumption not supported",
                session_id=res_summary,
                session_ticket=ticket_summary,
            )
    else:
        best["session_resumption"] = _info("Session resumption scan unavailable")

    # 17) DNS CAA
    try:
        has_caa, records = _dns_caa(hn)
        if has_caa:
            best["dns_caa"] = _pass("CAA records present", records=records)
        else:
            best["dns_caa"] = _warn("No CAA records found")
    except Exception as e:
        best["dns_caa"] = _info("CAA lookup failed", error=str(e))

    # Compile final json-like structure
    return {
        "certificate": {k: asdict(v) for k, v in cert.items()},
        "protocols": {k: asdict(v) for k, v in protocols.items()},
        "ciphers": {k: asdict(v) for k, v in ciphers.items()},
        "vulnerabilities": {k: asdict(v) for k, v in vulns.items()},
        "best_practices": {k: asdict(v) for k, v in best.items()},
    }

# def scan_and_export(sites, output_file="scan_results.txt"):
#     all_results = {}

#     for site in sites:
#         try:
#             print(f"=== Scanning {site} ===")
            
#             all_results[site] = results
#         except Exception as e:
#             all_results[site] = {"error": str(e)}

#     # Write to file with JSON formatting
#     with open(output_file, "w") as f:
#         json.dump(all_results, f, indent=4)

#     print(f"\n✅ Scan completed. Results saved to {output_file}")

if len(sys.argv) < 2:
    print("Usage: python ssl_checks.py <URL>")
    sys.exit(1)

target_url = sys.argv[1]
print(f"received target url {target_url}")
output_file = "scan_file.json"

all_results = {}

try:
    result = run_ssl_checks(target_url)   # run your function
    all_results[target_url] = result
    # Save JSON output
    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=4)

    print(f"\n✅ Scan completed. Results saved to {output_file}")


except Exception as e:
    print("Error in scanning url {target_url}: {e}")
