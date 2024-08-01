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


def verify_private_keys(pubkey: str, privkey: str, curve):
    vk_expected = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey), curve=curve)
    sk = ecdsa.SigningKey.from_secret_exponent(secexp=privkey, curve=curve)
    vk = sk.get_verifying_key()

    assert vk == vk_expected


def verify_nonce(r: str, nonce: int, curve=ecdsa.SECP256k1):
    r = int(r, 16)
    assert (curve.generator * nonce).x() == r


def derive_private_key_from_repeated_nonces(
    r_str: str, s: list[str], h: list[str], curve: Curve
):
    if len(set(s)) != 2 or len(set(h)) != 2:
        raise ValueError(
            "Two distinct 's' and two distinct digest values are expected."
        )
    # Data
    r = int(r_str, 16)
    s1, s2 = int(s[0], base=16), int(s[1], base=16)
    h1_str, h2_str = h[0], h[1]
    h1, h2 = (
        int(h1_str, base=16),
        int(h2_str, base=16),
    )

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
                vk.verify_digest(
                    bytes.fromhex(f"{r:064x}{s1:064x}"),
                    bytes.fromhex(h1_str),
                )
                vk.verify_digest(
                    bytes.fromhex(f"{r:064x}{s2:064x}"),
                    bytes.fromhex(h2_str),
                )
                return {"nonce": nonce, "private_key": priv_key}
            except Exception as e:
                raise e

    raise ValueError(
        "The nonce and the private key could not be recovered: the input signatures are probably invalid."
    )
