from typing import Callable
import ecdsa
from ecdsa.curves import Curve


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
