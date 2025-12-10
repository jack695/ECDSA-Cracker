from copy import deepcopy
import itertools
from typing import Callable
import ecdsa
from ecdsa.curves import Curve
from sympy import Matrix


def is_signature_valid(
    pubkey: str,
    r: str,
    s: str,
    h: str,
    curve: Curve,
    hashfunc: Callable | None = None,
):
    try:
        vk = ecdsa.VerifyingKey.from_string(
            bytes.fromhex(pubkey), curve=curve, hashfunc=hashfunc
        )
        vk.verify_digest(
            bytes.fromhex(f"{int(r, 16):064x}" + f"{int(s, 16):064x}"),
            bytes.fromhex(h),
        )
        return True
    except Exception:
        return False


def verify_private_key(pubkey: str, privkey: int, curve: Curve):
    vk_expected = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey), curve=curve)
    sk = ecdsa.SigningKey.from_secret_exponent(secexp=privkey, curve=curve)
    vk = sk.get_verifying_key()

    assert vk == vk_expected


def verify_nonce(r: int, nonce: int, curve=ecdsa.SECP256k1):
    assert (curve.generator * nonce).x() == r


def derive_private_key_from_repeated_nonces(
    r: int, s: list[int], h: list[int], pubkey: str, curve: Curve
):
    if len(set(s)) != 2 or len(set(h)) != 2:
        raise ValueError(
            "Two distinct 's' and two distinct digest values are expected."
        )
    # Data
    s1, s2 = s[0], s[1]
    h1, h2 = h[0], h[1]

    # Typecasting & constants
    order = curve.order
    generator = curve.generator

    for s1, s2 in [
        [s1, s2],
        [order - s1, s2],
        [s1, order - s2],
        [order - s1, order - s2],
    ]:
        # Nonce derivation
        s_diff_inv = pow((s1 - s2), -1, order)
        nonce = ((h1 - h2) * s_diff_inv) % order
        if r == (nonce * generator).x():
            priv_key = pow(r, -1, order) * (s2 * nonce - h2) % order
            sk = ecdsa.SigningKey.from_secret_exponent(
                secexp=priv_key, curve=curve, hashfunc=None
            )
            vk = sk.get_verifying_key()
            try:
                # Check the validity of the private key, as we might have recovered -k if the user has published -s1 and -s2 (which are still valid) over the network.
                verify_private_key(pubkey, priv_key, curve=curve)
                return {"nonce": nonce, "private_key": priv_key}
            except Exception as e:
                raise e

    raise ValueError(
        "The nonce and the private key could not be recovered: the input signatures are probably invalid."
    )


def derive_private_key_from_known_nonce(
    r: int, s: int, h: int, nonce: int, pubkey: str, curve: Curve
):
    order = curve.order

    expected_vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey), curve=curve)
    # We have to be careful that for a given nonce and given signature, 2 private keys are valid, see ecdsa_tutorial (mirror_key)
    priv_key = pow(r, -1, order) * (s * nonce - h) % order
    sk = ecdsa.SigningKey.from_secret_exponent(
        secexp=priv_key, curve=curve, hashfunc=None
    )
    vk = sk.get_verifying_key()

    if vk != expected_vk:
        nonce = (order - nonce) % order
        # Let's fetch the alternative private key, that could have signed that message
        priv_key = (pow(r, -1, order) * s * (2 * nonce) + priv_key) % order
        sk = ecdsa.SigningKey.from_secret_exponent(
            secexp=priv_key, curve=curve, hashfunc=None
        )
        vk = sk.get_verifying_key()

        assert vk == expected_vk

    return priv_key


def derive_nonce_from_known_private_key(
    r: int, s: int, h: int, d: int, curve=ecdsa.SECP256k1
):
    nonce = (pow(s, -1, curve.order) * (h + r * d)) % curve.order

    assert (nonce * curve.generator).x() == r

    return nonce


def solve(m, b, pos, pubkeys, r, curve=ecdsa.SECP256k1):
    m = deepcopy(m)

    for x in pos:
        for j in range(len(b) // 2):
            m[x][j] = -m[x][j] % ecdsa.SECP256k1.order if m[x][j] != 0 else 0

    m = Matrix(m)
    b = Matrix(b)
    sol = m.inv_mod(ecdsa.SECP256k1.order) * b % ecdsa.SECP256k1.order

    private_keys = {}
    for s in sol[len(b) // 2 :]:
        sk = ecdsa.SigningKey.from_secret_exponent(
            secexp=s,
            curve=ecdsa.SECP256k1,
        )
        vk = sk.get_verifying_key()
        pubkey = vk.to_string("compressed").hex()
        private_keys[pubkey] = s

    if set(private_keys.keys()) == set(pubkeys):
        nonces = {}
        for nonce in sol[: len(b) // 2]:
            r = (curve.generator * nonce).x()
            nonces[r] = nonce

        return nonces, private_keys
    return None, None


def solve_for_all_alterations(m, b, pubkeys, r):
    pos_s = [i for i in range(len(b))]
    for L in range(len(pos_s) + 1):
        for subset in itertools.combinations(pos_s, L):
            nonces, priv_keys = solve(m, b, subset, pubkeys, r)
            if nonces and priv_keys:
                assert set(nonces.keys()) == set(r)
                return nonces, priv_keys

    raise ValueError("The private keys could not be recovered.")
