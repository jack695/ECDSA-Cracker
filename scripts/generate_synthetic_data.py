'''
 # @ Author: Vincent Jacquot
 # @ Create Time: 2024-10-09 11:45:37
 # @ Description: A util script to generate synthetic (i.e. factice) signatures.
 '''

import argparse
import numpy as np
import random
import time
import ecdsa
import ecdsa.util
import string
import hashlib
import pandas as pd
import os

def generate_random_date(medium_date:str="2022-01-28 18:00:00", year_range: int = 1) -> np.datetime64:
    ms_range = year_range * 365 * 24 * 60 * 60
    return np.datetime64(medium_date) + random.randint(- ms_range, + ms_range)

def generate_random_digest() -> str:
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(256))

    h = hashlib.sha256(result_str.encode())

    return h.hexdigest()

def generate_random_sk_vk(curve: ecdsa.curves.Curve) -> tuple[ecdsa.SigningKey, ecdsa.VerifyingKey]:
    sk = ecdsa.SigningKey.from_secret_exponent(secexp=random.randint(1, 2*256), curve=curve)
    vk:ecdsa.VerifyingKey = sk.get_verifying_key() # type: ignore

    return sk, vk

def generate_random_signature(sk: ecdsa.SigningKey, vk: ecdsa.VerifyingKey, digest: str, nonce:int, curve: ecdsa.curves.Curve) -> tuple[str, str]:
    sig = sk.sign_digest(digest=bytes.fromhex(digest), k=nonce)
    r, s = ecdsa.util.sigdecode_string(sig, curve.order)

    return hex(r)[2:], hex(s)[2:] # r and s values are stored as string to circumvent limitations of encoding, i.e. to avoid error "Python int too large to convert to C long"

def generate_signatures(out_file: str) -> None:
    random.seed(time.time())
    data = []
    sks, vks = [], []
    sig_cnt = 0

    CURVE = ecdsa.SECP256k1
    KEY_CNT, REUSING_NONCE_KEY_CNT = 10, 3
    SIG_PER_KEY, REPEATED_SIG_PER_KEY = 1, 2

    # Generate a set of {key_cnt} key pairs
    for i in range(KEY_CNT):
        sk, vk = generate_random_sk_vk(CURVE)
        sks.append(sk)
        vks.append(vk)

    # Generate simple signatures for every key
    for sk, vk in zip(sks, vks):
        for i in range(SIG_PER_KEY):
            nonce = random.randint(1, 2**256)
            digest = generate_random_digest()
            r, s, = generate_random_signature(sk, vk, digest, nonce, CURVE)
            sig_id = f"sig_{sig_cnt}"
            sig_cnt += 1
            timestamp = generate_random_date()
            data.append([sig_id, timestamp, r, s, digest, vk.to_string(encoding="compressed").hex()])

    # Generate signatures on repeated nonces
    for i in random.sample(range(len(sks)), k=REUSING_NONCE_KEY_CNT):
        sk, vk = sks[i], vks[i]

        nonce = random.randint(1, 2**256)
        for i in range(REPEATED_SIG_PER_KEY):
            digest = generate_random_digest()
            r, s, = generate_random_signature(sk, vk, digest, nonce, CURVE)
            sig_id = f"sig_{sig_cnt}"
            sig_cnt += 1
            timestamp = generate_random_date()
            data.append([sig_id, timestamp, r, s, digest, vk.to_string(encoding="compressed").hex()])

    # Generate signatures for 1 equation system
    indices =  random.sample(range(len(sks)), k=2)
    sk0, vk0 = sks[indices[0]], vks[indices[0]]
    sk1, vk1 = sks[indices[1]], vks[indices[1]]

    nonce_a, nonce_b = random.randint(1, 2**256), random.randint(1, 2**256)
    for sk, vk, nonce in zip([sk0, sk0, sk1, sk1], [vk0, vk0, vk1, vk1], [nonce_a, nonce_b, nonce_a, nonce_b]):
        digest = generate_random_digest()
        r, s, = generate_random_signature(sk, vk, digest, nonce, CURVE)
        sig_id = f"sig_{sig_cnt}"
        sig_cnt += 1
        timestamp = generate_random_date()
        data.append([sig_id, timestamp, r, s, digest, vk.to_string(encoding="compressed").hex()])

    df = pd.DataFrame(data, columns=["sig_id", "timestamp", "r", "s", "message digest", "pubkey"])
    df["timestamp"] = df["timestamp"].dt.tz_localize("UTC")
    df.to_parquet(out_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("out", help="The output file path.")
    args = parser.parse_args()

    generate_signatures(args.out)
