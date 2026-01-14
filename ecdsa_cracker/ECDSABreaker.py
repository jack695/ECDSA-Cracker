import os
import ecdsa
from ecdsa.curves import Curve
from ecdsa_cracker.SignatureDB import SignatureDB, SignatureFolder
from ecdsa_cracker.ecdsa_helper import (
    derive_nonce_from_known_private_key,
    derive_private_key_from_known_nonce,
    derive_private_key_from_repeated_nonces,
    solve_for_all_alterations,
)
import logging

from ecdsa_cracker.graph_utils.Propagater import Propagater

logger = logging.getLogger(__name__)
logging.basicConfig(
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s: %(message)s",
    datefmt="%m/%d/%Y %H:%M:%S",
)


class ECDSABreaker:
    def __init__(self, db: SignatureDB, curve: Curve, out_folder: str) -> None:
        self.db = db
        self.log_stats()
        self.curve = curve
        if not os.path.exists(out_folder):
            os.makedirs(out_folder)
        self.out_folder = out_folder

    @classmethod
    def from_scratch(
        cls, signature_folders: list[SignatureFolder], curve: Curve, out_folder: str
    ):
        logger.info(
            "Loading the signatures... This might take some time especially if the option to check the signatures is enabled."
        )
        db = SignatureDB.from_scratch(signature_folders, curve=curve)

        return cls(db, curve, out_folder)

    @classmethod
    def from_dump(cls, dump_dir_path: str, curve: Curve, out_folder: str):
        logger.info("Restoring the database from a previous run...")
        db = SignatureDB.from_dump(dump_dir_path, curve=curve)

        return cls(db, curve, out_folder)

    def crack(self):
        logger.info("ROUND 0: Derive nonces and private keys from repeated nonces")
        self.__crack_repeated_nonces()
        self.log_stats(level=1)

        logger.info(
            "ROUND 1: Derive nonces and private keys from signatures that form a system of linear equations."
        )
        self.__crack_from_sig_equation_system()
        self.log_stats(level=1)

        logger.info(
            "ROUND 2: Derive nonces from known private keys and private keys from known nonces"
        )
        self.__crack_from_known_nonces_and_keys()
        self.log_stats(level=1)

        logger.info("-" * 25 + "RESULTS: " + "-" * 25)
        self.log_stats()
        self.db.dump_db(self.out_folder)

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
        repeated_nonces_df["vulnerability_source"] = "repeated_nonces"

        self.db.expand_known_nonce(repeated_nonces_df)
        self.db.expand_cracked_keys(repeated_nonces_df)

    def __crack_from_known_nonces_and_keys(self):
        uncracked_keys_df = self.db.uncracked_keys_df
        uncracked_keys_df = (
            uncracked_keys_df.sort_values(by="timestamp")
            .groupby(by=["r", "pubkey"], sort=False)
            .head(1)
        )

        cracked_keys_df = self.db.cracked_keys_df
        cracked_keys_df = (
            cracked_keys_df.sort_values(by="vulnerable_timestamp")
            .groupby(by=["pubkey"], sort=False)
            .head(1)
        )

        known_nonces_df = self.db.known_nonces_df.reset_index()

        propagater = Propagater(uncracked_keys_df, cracked_keys_df, known_nonces_df)
        propagater.propagate()

        cracked_keys_df = propagater.build_cracked_keys_df()
        self.db.expand_cracked_keys(cracked_keys_df)

        cracked_nonces_df = propagater.build_known_nonces_df()
        self.db.expand_known_nonce(cracked_nonces_df)

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
            f"   {cycle_signatures["cycle_id"].nunique()} basis cycles have been found in the bi-partite graph formed by the public keys and 'r' values.",
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
            rows["vulnerable_timestamp"] = rows["timestamp"].max()
            rows["vulnerability_source"] = "equation_system"
            rows["lineage"] = rows.apply(lambda _: rows["sig_id"].to_list(), axis=1)
            self.db.expand_cracked_keys(rows)

            rows["nonce"] = rows.apply(lambda row: nonces[row["r"]], axis=1)
            self.db.expand_known_nonce(rows)

        cycle_signatures.reset_index()
