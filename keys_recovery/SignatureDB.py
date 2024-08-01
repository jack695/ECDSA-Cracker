from collections import namedtuple
from typing import Annotated, Tuple
import pandas as pd
import glob
import os
from keys_recovery.ecdsa_helper import is_signature_valid
from ecdsa.curves import Curve
import logging
import networkx as nx
import pandera as pa
from pandera.typing import DataFrame


UncrackedSignaturesSchema = pa.DataFrameSchema(
    {
        "chain": pa.Column(str),
        "block_timestamp": pa.Column("datetime64[ms, UTC]"),
        "r": pa.Column(object),
        "s": pa.Column(object),
        "h": pa.Column(object),
        "pubkey": pa.Column(str),
    }
)

CrackedSignaturesSchema = pa.DataFrameSchema(
    {
        "chain": pa.Column(str),
        "vulnerable_timestamp": pa.Column("datetime64[ms, UTC]"),
        "r": pa.Column(object),
        "pubkey": pa.Column(str),
        "privkey": pa.Column(object),
        "r_chain": pa.Column(str),
    }
)

KnownNoncesSchema = pa.DataFrameSchema(
    {
        "r": pa.Column(object),
        "nonce": pa.Column(object),
        "r_chain": pa.Column(str),
        "vulnerable_timestamp": pa.Column("datetime64[ms, UTC]"),
    }
)

CrackableSignaturesSchema = pa.DataFrameSchema(
    {
        "chain": pa.Column(str),
        "r": pa.Column(object),
        "s": pa.Column(object),
        "h": pa.Column(object),
        "pubkey": pa.Column(str),
        "nonce": pa.Column(object),
        "r_chain": pa.Column(str),
        "vulnerable_timestamp": pa.Column("datetime64[ms, UTC]"),
    }
)

CrackableNoncesSchema = pa.DataFrameSchema(
    {
        "r": pa.Column(object),
        "s": pa.Column(object),
        "h": pa.Column(object),
        "pubkey": pa.Column(str),
        "vulnerable_timestamp": pa.Column("datetime64[ms, UTC]"),
        "privkey": pa.Column(object),
        "r_chain": pa.Column(str),
    }
)


logger = logging.getLogger(__name__)
logging.basicConfig(encoding="utf-8", level=logging.DEBUG)

SignatureFolder = namedtuple(
    "SignatureFolder", ["path", "check_signatures"], defaults=(False,)
)


class SignatureDB:

    def __init__(self, signature_folders: list[SignatureFolder], curve: Curve):
        self.curve = curve
        logger.info(
            "Loading the signatures. This might take some time especially if the option to check the signatures is enabled."
        )
        self._uncracked_keys_df = self._fetch_data(signature_folders)
        self._cracked_keys_df = pd.DataFrame()
        self._known_nonces_df = pd.DataFrame()

        logger.info(
            f"{self._uncracked_keys_df["pubkey"].nunique()} distinct private keys to recover."
        )

    def find_repeated_nonces(self) -> pd.DataFrame:
        # Group by pubkey and r. Keep two records for every row.
        grouped_df = (
            self._uncracked_keys_df.sort_values(by=["block_timestamp"])
            .groupby(by=["pubkey", "r", "s", "h"], sort=False)
            .head(1)
            .groupby(by=["pubkey", "r"], sort=False)
            .aggregate(
                s_cnt=("s", "nunique"),
                digest_cnt=("h", "nunique"),
                s=("s", lambda s: s.drop_duplicates().head(2)),
                digests=("h", lambda s: s.drop_duplicates().head(2)),
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
        nonces_df = nonces_df.reset_index()[KnownNoncesSchema.columns.keys()]
        KnownNoncesSchema.validate(nonces_df)
        nonces_df = nonces_df.set_index(keys="r")

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
        cracked_keys_df = cracked_keys_df[CrackedSignaturesSchema.columns.keys()]
        CrackedSignaturesSchema.validate(cracked_keys_df)

        self._cracked_keys_df = pd.concat([self._cracked_keys_df, cracked_keys_df])
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
        crackable_keys = crackable_keys.drop(columns=["block_timestamp"])

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
            .rename(columns={"chain": "r_chain"})
        )
        crackable_nonces["vulnerable_timestamp"] = crackable_nonces[
            ["block_timestamp", "vulnerable_timestamp"]
        ].max(axis=1)
        crackable_nonces = crackable_nonces.drop(columns=["block_timestamp"])

        CrackableSignaturesSchema.validate(crackable_keys)
        CrackableNoncesSchema.validate(crackable_nonces)

        return crackable_keys, crackable_nonces

    def get_cycle_signatures(self) -> list[DataFrame]:
        """Return a list of dataframes, each of them represents a cycle among the bi-partite graph of uncracked keys and uncracked 'r' values.

        A cycle in this bi-partite graph going through n distinct public keys and n distinct r values is composed of 2n signatures.
        Thus, this set of 2n signatures can be translated as a system of linear equations that has a unique solution.
        """

        def get_rows_from_cycle(df, cycle):
            to_fetch = []

            for node, next_node in zip(cycle, cycle[1:] + [cycle[0]]):
                if ":" in node:
                    pk = node.split(":")[1]
                    r = next_node
                else:
                    pk = next_node.split(":")[1]
                    r = node
                to_fetch.append((pk, r))

            return df.loc[to_fetch].sort_index().reset_index()

        uncracked_keys_df = self._uncracked_keys_df
        uncracked_keys_df["pubkey_chain"] = (
            uncracked_keys_df["chain"] + ":" + uncracked_keys_df["pubkey"]
        )

        # Look for basis cycles
        G = nx.Graph()
        G.add_edges_from(uncracked_keys_df[["pubkey_chain", "r"]].to_numpy().tolist())
        cycles = nx.cycle_basis(G)
        logger.info(
            f"{len(cycles)} basis cycles have been found in the bi-partite graph of uncracked keys."
        )

        cycle_rows, indexed_df = [], uncracked_keys_df.set_index(keys=["pubkey", "r"])
        for cycle in cycles:
            rows = get_rows_from_cycle(indexed_df, cycle)
            UncrackedSignaturesSchema.validate(rows)
            cycle_rows.append(rows)
        return cycle_rows

    def _fetch_data(self, signature_folders: list[SignatureFolder]) -> pd.DataFrame:
        chunks = []
        for folder in signature_folders:
            signatures_files = glob.glob(os.path.join(folder.path, "*.parquet"))
            chunk = pd.concat(
                pd.read_parquet(parquet_file) for parquet_file in signatures_files
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

        sig_df = pd.concat(chunks)
        # Let's use the native python int to support any size to support different schemes and curve despite the loss of performance.
        sig_df["r"] = sig_df["r"].apply(lambda r: int(r, 16))
        sig_df["s"] = sig_df["s"].apply(lambda r: int(r, 16))
        sig_df["h"] = sig_df["message digest"].apply(lambda r: int(r, 16))
        sig_df = sig_df.drop(
            columns=["message digest", "transaction_hash", "input_index"]
        )

        UncrackedSignaturesSchema.validate(sig_df)
        return sig_df
