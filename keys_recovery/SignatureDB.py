from collections import namedtuple
from pydoc import locate
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
    KnownNoncesSchema,
    UncrackedCyclingSignaturesSchema,
    UncrackedSignaturesSchema,
    check_output_format,
    check_input_format,
)

SignatureFolder = namedtuple(
    "SignatureFolder", ["path", "check_signatures"], defaults=(False,)
)


class SignatureDB:

    UNCRACKED_SIG_FILE = "uncracked_keys_df.parquet"
    CRACKED_SIG_FILE = "cracked_keys_df.parquet"
    KNOWN_NONCES_FILE = "known_nonces_df.parquet"

    def __init__(
        self,
        uncracked_keys_df: pd.DataFrame,
        cracked_keys_df: pd.DataFrame,
        known_nonces_df: pd.DataFrame,
        curve: Curve,
    ):
        self.curve = curve
        self._uncracked_keys_df = uncracked_keys_df
        self._cracked_keys_df = cracked_keys_df
        self._known_nonces_df = known_nonces_df

        self._n_pubkeys = self._uncracked_keys_df["pubkey"].nunique()
        self._n_r = self._uncracked_keys_df["r"].nunique()

    @classmethod
    def from_scratch(cls, signature_folders: list[SignatureFolder], curve: Curve):
        uncracked_keys_df = cls._fetch_data(signature_folders, curve)
        cracked_keys_df = pd.DataFrame(
            columns=CrackedSignaturesSchema.columns,
            dtype=CrackedSignaturesSchema.dtype,
        )
        known_nonces_df = pd.DataFrame(
            columns=KnownNoncesSchema.columns, dtype=KnownNoncesSchema.dtype
        )

        return cls(uncracked_keys_df, cracked_keys_df, known_nonces_df, curve)

    @classmethod
    def from_dump(cls, dump_dir_path: str, curve: Curve):
        uncracked_keys_dump_path = os.path.join(dump_dir_path, cls.UNCRACKED_SIG_FILE)
        uncracked_keys_df = cls.convert_rsh(pd.read_parquet(uncracked_keys_dump_path))

        cracked_keys_dump_path = os.path.join(dump_dir_path, cls.CRACKED_SIG_FILE)
        cracked_keys_df = cls.convert_rsh(pd.read_parquet(cracked_keys_dump_path))
        cracked_keys_df["lineage"] = cracked_keys_df["lineage"].apply(list)

        known_nonces_dump_path = os.path.join(dump_dir_path, cls.KNOWN_NONCES_FILE)
        known_nonces_df = cls.convert_rsh(pd.read_parquet(known_nonces_dump_path))
        known_nonces_df["lineage"] = known_nonces_df["lineage"].apply(list)

        return cls(uncracked_keys_df, cracked_keys_df, known_nonces_df, curve)

    def dump_db(self, out_dir: str):
        uncracked_keys_dump_path = os.path.join(out_dir, self.UNCRACKED_SIG_FILE)
        self.convert_rsh(self._uncracked_keys_df.copy(), to_int=False).to_parquet(
            uncracked_keys_dump_path
        )

        cracked_keys_dump_path = os.path.join(out_dir, self.CRACKED_SIG_FILE)
        self.convert_rsh(self._cracked_keys_df.copy(), to_int=False).to_parquet(
            cracked_keys_dump_path
        )

        known_nonces_dump_path = os.path.join(out_dir, self.KNOWN_NONCES_FILE)
        self.convert_rsh(self._known_nonces_df.copy(), to_int=False).to_parquet(
            known_nonces_dump_path
        )

    @property
    @check_output_format(UncrackedSignaturesSchema)
    def uncracked_keys_df(self):
        return self._uncracked_keys_df

    @property
    @check_output_format(CrackedSignaturesSchema)
    def cracked_keys_df(self):
        return self._cracked_keys_df

    @property
    @check_output_format(KnownNoncesSchema)
    def known_nonces_df(self):
        return self._known_nonces_df

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
                s=("s", lambda s: s.head(2).to_list()),
                digests=("h", lambda s: s.head(2).to_list()),
                lineage=("sig_id", lambda s: s.head(2).to_list()),
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
            self._cracked_keys_df = (
                self._cracked_keys_df.sort_values(by="vulnerable_timestamp")
                .groupby(by="pubkey", sort=False)
                .head(1)
            )

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
                pk, r = (
                    (node, next_node)
                    if type(node)
                    is locate(str(UncrackedCyclingSignaturesSchema.dtypes["pubkey"]))
                    else (next_node, node)
                )
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

    def build_lineage(self, pubkey: str):
        cracked_keys_df = self._cracked_keys_df.set_index("pubkey")
        known_nonces_df = self._known_nonces_df.set_index("r")

        lineage = []
        r_side = False
        key, df = pubkey, cracked_keys_df
        vulnerability_source = df.loc[key].vulnerability_source

        while key:
            lineage.append(
                (
                    key,
                    vulnerability_source,
                    df.loc[key].lineage,
                    df.loc[key].vulnerable_timestamp,
                )
            )

            # Next iteration
            if vulnerability_source in ["repeated_nonces", "equation_system"]:
                key = None
            else:
                if r_side:
                    key = vulnerability_source.split(":")[1]
                    df = cracked_keys_df
                else:
                    key = int(vulnerability_source.split(":")[1])
                    df = known_nonces_df
                r_side = not r_side
                vulnerability_source = df.loc[key].vulnerability_source

        return lineage

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

    @classmethod
    @check_output_format(UncrackedSignaturesSchema)
    def _fetch_data(
        cls, signature_folders: list[SignatureFolder], curve: Curve
    ) -> pd.DataFrame:
        chunks = []
        for folder in signature_folders:
            signatures_files = glob.glob(os.path.join(folder.path, "*.parquet"))
            for parquet_file in signatures_files:
                # Some signatures do not have an 'input' index field, e.g. eth calls.
                chunk = pd.read_parquet(parquet_file).fillna("")
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
                                curve=curve,
                            ),
                            axis=1,
                        )
                    ]
                )
                chunks.append(chunk)

        sig_df = pd.concat(chunks)
        # Let's use the native python int to support any size to support different schemes and curve despite the loss of performance.
        sig_df = sig_df.rename(columns={"message digest": "h"})
        sig_df = cls.convert_rsh(sig_df)
        sig_df["sig_id"] = sig_df["chain"].str.cat(
            [sig_df["transaction_hash"], sig_df["input_index"].astype(str)],
            sep=":",
        )
        # TODO check that the public keys are encoded using the compressed format

        return sig_df

    @classmethod
    def convert_rsh(cls, sig_df: pd.DataFrame, to_int: bool = True) -> pd.DataFrame:
        cols = ["r", "s", "h", "nonce", "privkey"]
        if to_int:
            for col in cols:
                if col in sig_df.columns:
                    sig_df[col] = sig_df[col].apply(lambda val: int(val, 16))
            return sig_df
        else:
            for col in cols:
                if col in sig_df.columns:
                    sig_df[col] = sig_df[col].apply(hex)
            return sig_df
