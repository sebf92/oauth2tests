"""
DPoP cryptography helpers — RFC 9449 Demonstrating Proof-of-Possession.

Pure utility module extracted from ``app.py``: no Flask coupling, no session
state.  Used by:

  • ``/auth/dpop`` route (full DPoP flow demo)
  • ``/auth/pkce`` route (re-uses ``_b64url`` for code_verifier encoding)

This module is the canonical home of ``_b64url`` for the client-app; other
modules import it from here rather than redefining it.
"""

import base64
import hashlib
import json
import secrets
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def _b64url(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def generate_dpop_keypair():
    """
    Generate an ephemeral EC P-256 key pair for a single DPoP session.

    Returns (private_key, public_jwk_dict).  The key is created in memory and
    never persisted — generating a new pair per request is intentional: DPoP
    proof tokens carry a unique jti so they cannot be replayed, and the key pair
    being short-lived means a stolen proof is useless after the session ends.
    P-256 (secp256r1) is required by RFC 9449 §4 for the ES256 algorithm.
    """
    priv = generate_private_key(SECP256R1(), default_backend())
    nums = priv.public_key().public_numbers()
    pub_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x":   _b64url(nums.x.to_bytes(32, "big")),
        "y":   _b64url(nums.y.to_bytes(32, "big")),
    }
    return priv, pub_jwk


def jwk_thumbprint(pub_jwk: dict) -> str:
    """Compute the RFC 7638 JWK thumbprint (SHA-256 of canonical key members)."""
    canonical = json.dumps(
        {"crv": pub_jwk["crv"], "kty": pub_jwk["kty"], "x": pub_jwk["x"], "y": pub_jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return _b64url(hashlib.sha256(canonical.encode()).digest())


def make_dpop_proof(
    priv_key,
    pub_jwk: dict,
    htm: str,
    htu: str,
    access_token: str | None = None,
) -> str:
    """
    Build a signed DPoP proof JWT (RFC 9449 §4.2).

    htm            HTTP method in uppercase ("POST", "GET", …).
    htu            Full URI without query string or fragment.  Keycloak validates
                   the htu in the token-endpoint proof against the URL it actually
                   received the request at — use KC_TOKEN_URL, not the public URL.
    access_token   When calling a resource server, pass the access token so the
                   ath claim (SHA-256 of the token) is included.  ath binds the
                   proof to a specific token, preventing an attacker from reusing
                   a captured proof with a different (stolen) access token.

    Two proofs are needed per DPoP flow:
      Proof 1 → token endpoint  (htm=POST, no ath — token not yet obtained)
      Proof 2 → resource server (htm=GET,  ath=SHA-256(access_token))
    """
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": pub_jwk}
    claims = {"jti": secrets.token_urlsafe(16), "htm": htm, "htu": htu, "iat": int(time.time())}
    if access_token is not None:
        claims["ath"] = _b64url(hashlib.sha256(access_token.encode()).digest())

    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()

    der_sig = priv_key.sign(signing_input, ECDSA(crypto_hashes.SHA256()))
    r, s    = decode_dss_signature(der_sig)
    # cryptography's sign() returns ASN.1 DER. ES256 (JWA) requires the raw
    # r || s encoding (two 32-byte big-endian integers, no framing). We extract
    # r and s via decode_dss_signature and re-encode manually.
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{h_b64}.{p_b64}.{_b64url(raw_sig)}"
