from collections import namedtuple
from typing import Tuple
import pandas as pd
import glob
import os
from keys_recovery.ecdsa_helper import is_signature_valid
from ecdsa.curves import Curve
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(encoding="utf-8", level=logging.DEBUG)

SignatureFolder = namedtuple(
    "SignatureFolder", ["path", "check_signatures"], defaults=(False,)
)


class SignatureDB:
    UNCRACKED_SIGNATURES_DTYPES = {
        "chain": "string[pyarrow]",
        "block_timestamp": "datetime64[s, UTC]",
        "r": "string[pyarrow]",
        "s": "string[pyarrow]",
        "message digest": "string[pyarrow]",
        "pubkey": "string[pyarrow]",
    }

    CRACKED_SIGNATURES_DTYPES = {
        "chain": "string[pyarrow]",
        "vulnerable_timestamp": "datetime64[s, UTC]",
        "r": "string[pyarrow]",
        "pubkey": "string[pyarrow]",
        "privkey": "string[pyarrow]",
        "r_chain": "string[pyarrow]",
    }

    KNOWN_NONCES_DTYPES = {
        "r": "string[pyarrow]",
        "nonce": "object",  # Let's use the native python int to support any size
        "r_chain": "string[pyarrow]",
        "vulnerable_timestamp": "datetime64[s, UTC]",
    }

    CRACKABLE_SIGNATURES_DTYPES = {
        "chain": "string[pyarrow]",
        "r": "string[pyarrow]",
        "s": "string[pyarrow]",
        "message digest": "string[pyarrow]",
        "pubkey": "string[pyarrow]",
        "nonce": "object",  # Let's use the native python int to support any size
        "r_chain": "string[pyarrow]",
        "vulnerable_timestamp": "datetime64[s, UTC]",
    }

    CRACKABLE_NONCES_DTYPES = {
        "r": "string[pyarrow]",
        "s": "string[pyarrow]",
        "message digest": "string[pyarrow]",
        "pubkey": "string[pyarrow]",
        "vulnerable_timestamp": "datetime64[s, UTC]",
        "privkey": "string[pyarrow]",
        "r_chain": "string[pyarrow]",
    }

    def __init__(self, signature_folders: list[SignatureFolder], curve: Curve):
        self.curve = curve
        logger.info(
            "Loading the signatures. This might take some time especially if the option to check the signatures is enabled."
        )
        self._uncracked_keys_df = self._fetch_data(signature_folders)
        self._cracked_keys_df = pd.DataFrame(
            {c: pd.Series(dtype=t) for c, t in self.CRACKED_SIGNATURES_DTYPES.items()}
        )
        self._known_nonces_df = pd.DataFrame(
            {c: pd.Series(dtype=t) for c, t in self.KNOWN_NONCES_DTYPES.items()}
        ).set_index(keys="r")

        logger.info(
            f"{self._uncracked_keys_df["pubkey"].nunique()} distinct private keys to recover."
        )

    def find_repeated_nonces(self) -> pd.DataFrame:
        # Group by pubkey and r. Keep two records for every row.
        grouped_df = (
            self._uncracked_keys_df.sort_values(by=["block_timestamp"])
            .groupby(by=["pubkey", "r", "s", "message digest"], sort=False)
            .head(1)
            .groupby(by=["pubkey", "r"], sort=False)
            .aggregate(
                s_cnt=("s", "nunique"),
                digest_cnt=("message digest", "nunique"),
                s=("s", lambda s: s.drop_duplicates().head(2)),
                digests=("message digest", lambda s: s.drop_duplicates().head(2)),
                chain=("chain", lambda s: s.drop_duplicates()),
                vulnerable_timestamp=(
                    "block_timestamp",
                    lambda s: s.head(2).tail(1),
                ),  # The signatures and 'r' values become vulnerable as soon as the second signature is published
            )
        )
        # Keep the records in presence of a repeated nonce
        grouped_df = grouped_df[
            (grouped_df["s_cnt"] > 1) & (grouped_df["digest_cnt"] > 1)
        ].drop(columns=["s_cnt", "digest_cnt"])

        return grouped_df.reset_index()

    def expand_known_nonce(self, nonces_df: pd.DataFrame):
        self._known_nonces_df = (
            pd.concat([self._known_nonces_df, nonces_df])
            .sort_values(by="vulnerable_timestamp")
            .groupby(by="r", sort=False)
            .head(1)
        )
        logger.info(
            f"{len(self._known_nonces_df.index)} distinct 'r' vulnerable values."
        )

    def expand_cracked_keys(self, cracked_keys_df: pd.DataFrame):
        self._cracked_keys_df = pd.concat([self._known_nonces_df, cracked_keys_df])
        self._uncracked_keys_df = (
            pd.merge(
                self._uncracked_keys_df,
                cracked_keys_df[["pubkey", "r"]],
                indicator=True,
                how="outer",
                on=["pubkey", "r"],
            )
            .query('_merge=="left_only"')
            .drop("_merge", axis=1)
        )

        logger.info(
            f"{self._uncracked_keys_df["pubkey"].nunique()} distinct private keys remain to recover."
        )
        logger.info(
            f"{self._cracked_keys_df["pubkey"].nunique()} distinct private keys recovered."
        )

    def get_crackable_keys_and_nonces(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Return 2 dataframes
        * The uncracked keys that could be recovered as they used known nonces.
        * The nonces that could be recovered thereafter as they were used by those private keys.
        """
        crackable_keys = pd.merge(
            self._uncracked_keys_df,
            self._known_nonces_df,
            on="r",
            how="inner",
        )
        crackable_keys["vulnerable_timestamp"] = crackable_keys[
            ["block_timestamp", "vulnerable_timestamp"]
        ].max(axis=1)
        crackable_keys.drop(columns=["block_timestamp"])

        crackable_nonces = (
            pd.merge(
                self._uncracked_keys_df,
                self._cracked_keys_df[
                    ["pubkey", "vulnerable_timestamp", "privkey", "r_chain"]
                ],
                how="inner",
                on="pubkey",
            )
            .drop(columns="r_chain")
            .rename({"chain": "r_chain"})
        )
        crackable_nonces["vulnerable_timestamp"] = crackable_nonces[
            ["block_timestamp", "vulnerable_timestamp"]
        ].max(axis=1)
        crackable_nonces.drop(columns=["block_timestamp"])

        return crackable_keys, crackable_nonces

    def _fetch_data(self, signature_folders: list[SignatureFolder]) -> pd.DataFrame:
        chunks = []
        for folder in signature_folders:
            signatures_files = glob.glob(os.path.join(folder.path, "*.parquet"))
            chunk = pd.concat(
                pd.read_parquet(
                    parquet_file, columns=list(self.UNCRACKED_SIGNATURES_DTYPES.keys())
                )  # .astype(self.UNCRACKED_SIGNATURES_DTYPES) # TODO: Activate
                for parquet_file in signatures_files
            )
            # Optional: round of filtering
            chunk = (
                chunk
                if not folder.check_signatures
                else chunk[
                    chunk.apply(
                        lambda row: is_signature_valid(
                            row["pubkey"],
                            row["r"],
                            row["s"],
                            row["message digest"],
                            curve=self.curve,
                        ),
                        axis=1,
                    )
                ]
            )
            chunks.append(chunk)

        return pd.concat(chunks)
