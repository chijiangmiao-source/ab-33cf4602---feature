"""Pure-Python Ed25519 (RFC 8032) signing and verification.

Only the standard library is used so the container image builds with no
network access and no third-party dependencies.  Points are represented in
extended twisted-Edwards coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z,
T = XY/Z, which keeps scalar multiplication free of modular inversions.

The verification equation follows RFC 8032 section 5.1.7 ("CheckValid"):
    [S]B == R + [H(R || A || M)]A
with canonical-encoding and on-curve checks on A and R, and S < L.
"""

from __future__ import annotations

import hashlib

# Field and group constants -------------------------------------------------
_P = 2**255 - 19  # prime field
_L = 2**252 + 27742317777372353535851937790883648493  # group order
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)  # sqrt(-1) mod p


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, (_BX * _BY) % _P)  # base point, extended coordinates
_IDENTITY = (0, 1, 1, 0)


def _add(p1: tuple, p2: tuple) -> tuple:
    """Unified addition formula (add-2008-hwcd-3); complete for a = -1."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalarmult(point: tuple, scalar: int) -> tuple:
    result = _IDENTITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _encode(point: tuple) -> bytes:
    x, y, z, _t = point
    zinv = pow(z, _P - 2, _P)
    xa = (x * zinv) % _P
    ya = (y * zinv) % _P
    return (ya | ((xa & 1) << 255)).to_bytes(32, "little")


def _decode(data: bytes) -> tuple:
    if len(data) != 32:
        raise ValueError("point encoding must be 32 bytes")
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = data[31] >> 7
    if y >= _P:
        raise ValueError("non-canonical point encoding")
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        raise ValueError("point is not on the curve")
    if x == 0 and sign == 1:
        raise ValueError("invalid encoding of the identity x-coordinate")
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, (x * y) % _P)


def _clamp(half: bytes) -> int:
    a = int.from_bytes(half, "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def publickey(seed: bytes) -> bytes:
    """Derive the 32-byte public key for a 32-byte secret seed."""
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("secret seed must be 32 bytes")
    a = _clamp(_sha512(seed)[:32])
    return _encode(_scalarmult(_B, a))


def sign(seed: bytes, message: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature over ``message``."""
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("secret seed must be 32 bytes")
    digest = _sha512(seed)
    a = _clamp(digest[:32])
    prefix = digest[32:]
    public = _encode(_scalarmult(_B, a))
    r = int.from_bytes(_sha512(prefix + message), "little") % _L
    r_enc = _encode(_scalarmult(_B, r))
    k = int.from_bytes(_sha512(r_enc + public + message), "little") % _L
    s = (r + k * a) % _L
    return r_enc + s.to_bytes(32, "little")


def verify(public: bytes, signature: bytes, message: bytes) -> bool:
    """Return True iff ``signature`` is a valid RFC 8032 signature."""
    if not isinstance(public, bytes) or len(public) != 32:
        return False
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    try:
        a_point = _decode(public)
        r_point = _decode(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(_sha512(signature[:32] + public + message), "little") % _L
    lhs = _scalarmult(_B, s)
    rhs = _add(r_point, _scalarmult(a_point, k))
    return _encode(lhs) == _encode(rhs)
