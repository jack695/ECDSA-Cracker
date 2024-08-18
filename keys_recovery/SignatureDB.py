from collections import namedtuple
from typing import Tuple
import pandas as pd
import glob
import os
from keys_recovery.ecdsa_helper import is_signature_valid
from ecdsa.curves import Curve
import networkx as nx
from lib.script_parser.utxo_utils.encoding.address import (
    generate_flatten_addresses,
)
from keys_recovery.dataframe_schemas import (
    CrackedSignaturesSchema,
    CrackableSignaturesSchema,
    CrackableNoncesSchema,
    KnownNoncesSchema,
    UncrackedCyclingSignaturesSchema,
    UncrackedSignaturesSchema,
    check_output_format,
)

SignatureFolder = namedtuple(
    "SignatureFolder", ["path", "check_signatures"], defaults=(False,)
)


class SignatureDB:

    def __init__(self, signature_folders: list[SignatureFolder], curve: Curve):
        self.curve = curve
        self._uncracked_keys_df = self._fetch_data(signature_folders)
        self._cracked_keys_df = pd.DataFrame(
            columns=CrackedSignaturesSchema.columns,
            dtype=CrackedSignaturesSchema.dtype,
        )
        self._known_nonces_df = pd.DataFrame(
            columns=KnownNoncesSchema.columns, dtype=KnownNoncesSchema.dtype
        ).set_index(keys="r")

        self._n_pubkeys = self._uncracked_keys_df["pubkey"].nunique()
        self._n_r = self._uncracked_keys_df["r"].nunique()

    def get_stats(self):
        return {
            "pubkeys_cnt": self._n_pubkeys,
            "r_cnt": self._n_r,
            "cracked_keys_cnt": self._cracked_keys_df["pubkey"].nunique(),
            "cracked_nonces_cnt": len(self._known_nonces_df),
        }

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

    @check_input_format(KnownNoncesSchema, 1)
    def expand_known_nonce(self, nonces_df: pd.DataFrame):
        nonces_df = nonces_df.set_index(keys="r")

        if self._known_nonces_df.empty:
            self._known_nonces_df = nonces_df.copy(deep=True)
        else:
            self._known_nonces_df = pd.concat([self._known_nonces_df, nonces_df])
            self._known_nonces_df = (
                self._known_nonces_df.sort_values(by="vulnerable_timestamp")
                .groupby(by="r", sort=False)
                .head(1)
            )

    @check_input_format(CrackedSignaturesSchema, 1)
    def expand_cracked_keys(self, cracked_keys_df: pd.DataFrame):
        if self._cracked_keys_df.empty:
            self._cracked_keys_df = cracked_keys_df.copy(deep=True)
        else:
            self._cracked_keys_df = pd.concat([self._cracked_keys_df, cracked_keys_df])
            self._cracked_keys_df.sort_values(by="vulnerable_timestamp").groupby(
                by="pubkey", sort=False
            ).head(1)

    @check_output_format(CrackableSignaturesSchema)
    def get_crackable_keys(self) -> pd.DataFrame:
        """Return the uncracked keys that could be recovered as they used known nonces."""
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

        crackable_keys = (
            crackable_keys.sort_values(by="vulnerable_timestamp")
            .groupby(by=["r", "pubkey"], sort=False)
            .head(1)
        )

        crackable_keys = (
            pd.merge(
                crackable_keys,
                self._cracked_keys_df[["pubkey", "r", "vulnerable_timestamp"]],
                indicator=True,
                how="outer",
                on=["pubkey", "r"],
                suffixes=(None, "_cracked_keys"),
            )
            .query(
                '_merge=="left_only" | vulnerable_timestamp < vulnerable_timestamp_cracked_keys'
            )  # Get keys that are not cracked yet or that would allow to crack the key earlier
            .drop(columns=["_merge", "vulnerable_timestamp_cracked_keys"], axis=1)
        )

        return crackable_keys

    @check_output_format(CrackableNoncesSchema)
    def get_crackable_nonces(self) -> pd.DataFrame:
        """Return the nonces that could be recovered thereafter as they were used by those private keys."""
        crackable_nonces = pd.merge(
            self._uncracked_keys_df,
            self._cracked_keys_df[["pubkey", "vulnerable_timestamp", "privkey"]],
            how="inner",
            on="pubkey",
        )
        crackable_nonces["vulnerable_timestamp"] = crackable_nonces[
            ["block_timestamp", "vulnerable_timestamp"]
        ].max(axis=1)
        crackable_nonces = crackable_nonces.drop(columns=["block_timestamp"])

        crackable_nonces = (
            crackable_nonces.sort_values(by="vulnerable_timestamp")
            .groupby(by=["r", "pubkey"], sort=False)
            .head(1)
        )
        crackable_nonces = (
            pd.merge(
                crackable_nonces,
                self._known_nonces_df.reset_index()[["r", "vulnerable_timestamp"]],
                indicator=True,
                how="outer",
                on=["r"],
                suffixes=(None, "_known_nonces"),
            )
            .query(
                '_merge=="left_only" | vulnerable_timestamp < vulnerable_timestamp_known_nonces'
            )  # Get nonces that are not yet known or that would allow to know the nonce earlier
            .drop(columns=["_merge", "vulnerable_timestamp_known_nonces"], axis=1)
        )

        return crackable_nonces

    @check_output_format(UncrackedCyclingSignaturesSchema)
    def get_cycle_signatures(self) -> pd.DataFrame:
        """Return a list of dataframes, each of them represents a cycle among the bi-partite graph of uncracked keys and uncracked 'r' values.

        A cycle in this bi-partite graph going through n distinct public keys and n distinct r values is composed of 2n signatures.
        Thus, this set of 2n signatures can be translated as a system of linear equations that has a unique solution.
        """
        # Look for basis cycles
        G = nx.Graph()
        G.add_edges_from(self._uncracked_keys_df[["pubkey", "r"]].to_numpy().tolist())
        cycles = nx.cycle_basis(G)

        indices_to_fetch = []
        for cycle_id, cycle in enumerate(cycles):
            for node, next_node in zip(cycle, cycle[1:] + [cycle[0]]):
                # TODO: Check Panderas docs to access the type of "pubkey" from the schema instead of hardcoding "str".
                pk, r = (node, next_node) if type(node) is str else (next_node, node)
                indices_to_fetch.append((cycle_id, pk, r))
        indexes_to_fetch_df = pd.DataFrame(
            indices_to_fetch, columns=["cycle_id", "pubkey", "r"]
        )

        cycle_rows = (
            self._uncracked_keys_df.merge(
                indexes_to_fetch_df, how="inner", on=["r", "pubkey"]
            )
            .sort_values(by="block_timestamp")
            .groupby(by=["r", "pubkey", "cycle_id"])
            .head(1)
        )

        return cycle_rows

    def save_addresses(self, out_file: str):
        all_private_keys_with_addresses = (
            self._cracked_keys_df[["pubkey", "vulnerable_timestamp"]]
            .sort_values(["vulnerable_timestamp"])
            .groupby(by=["pubkey"], sort=False)
            .head(1)
            .drop_duplicates()
            .reset_index()
        )
        all_private_keys_with_addresses[
            ["chain_address", "pubkey_format", "address"]
        ] = all_private_keys_with_addresses.apply(
            lambda row: generate_flatten_addresses(row["pubkey"]),
            axis=1,
            result_type="expand",
        )
        all_private_keys_with_addresses = all_private_keys_with_addresses.explode(
            ["chain_address", "pubkey_format", "address"]
        )
        all_private_keys_with_addresses.to_parquet(out_file)

    @check_output_format(UncrackedSignaturesSchema)
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
        sig_df["blockchain_source_id"] = sig_df.apply(
            lambda row: (
                row["chain"]
                + ":"
                + row["transaction_hash"]
                + ":"
                + str(row["input_index"])
            ),
            axis=1,
        )

        return sig_df
