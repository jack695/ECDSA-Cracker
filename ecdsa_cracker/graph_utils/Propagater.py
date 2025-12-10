from typing import Iterator, Type
import networkx as nx
import pandas as pd
from ecdsa_cracker.dataframe_schemas import CrackedSignaturesSchema, KnownNoncesSchema
from ecdsa_cracker.graph_utils.Node import KeyNode, Node, RNode
from ecdsa_cracker.graph_utils.Sig import Sig
import ecdsa


class Propagater:
    def __init__(
        self,
        uncracked_keys_df: pd.DataFrame,
        cracked_keys_df: pd.DataFrame,
        known_nonces_df: pd.DataFrame,
    ):
        self.G: nx.Graph = nx.Graph()
        self.__set_edges(uncracked_keys_df, cracked_keys_df, known_nonces_df)
        self.__post_checking(cracked_keys_df, known_nonces_df, uncracked_keys_df)

    def propagate(self):
        for prop_node in self._propagating_nodes:
            for n in self.G.neighbors(prop_node):
                n.propagate(self.G, prop_node)

    def build_cracked_keys_df(self):
        data = []
        for n in self.__get_cracked_nodes(KeyNode):
            data.append(
                [
                    n.pubkey,
                    n.privkey,
                    n.vulnerable_timestamp,
                    n.vulnerability_source,
                    n.lineage,
                ]
            )
        dtypes = {
            col: str(CrackedSignaturesSchema.dtypes[col])
            for col in CrackedSignaturesSchema.columns
        }
        dtypes.pop("lineage")
        return pd.DataFrame(
            data=data,
            columns=CrackedSignaturesSchema.columns,
        ).astype(dtypes)

    def build_known_nonces_df(self):
        data = []
        for n in self.__get_cracked_nodes(RNode):
            data.append(
                [
                    n.r,
                    n.nonce,
                    n.vulnerable_timestamp,
                    n.vulnerability_source,
                    n.lineage,
                ]
            )

        dtypes = {
            col: str(KnownNoncesSchema.dtypes[col]) for col in KnownNoncesSchema.columns
        }
        dtypes.pop("lineage")
        return pd.DataFrame(data=data, columns=KnownNoncesSchema.columns).astype(dtypes)

    def __get_cracked_nodes(
        self, nodeClass: Type[KeyNode | RNode]
    ) -> Iterator[KeyNode | RNode]:
        for n in self.G:
            if type(n) == nodeClass and n.cracked:
                yield n

    def __set_edges(
        self,
        uncracked_keys_df: pd.DataFrame,
        cracked_keys_df: pd.DataFrame,
        known_nonces_df: pd.DataFrame,
    ):
        self._propagating_nodes = set()

        r_nodes = {}
        key_nodes = {}
        edges = []
        for tuple in uncracked_keys_df.itertuples():
            if tuple.r not in r_nodes:
                r_node = RNode(tuple.r, ecdsa.SECP256k1)  # type: ignore
                r_nodes[tuple.r] = r_node

            if tuple.pubkey not in key_nodes:
                key_node = KeyNode(tuple.pubkey, ecdsa.SECP256k1)  # type: ignore
                key_nodes[tuple.pubkey] = key_node

            sig = Sig(
                tuple.pubkey,  # type: ignore
                tuple.r,  # type: ignore
                tuple.s,  # type: ignore
                tuple.h,  # type: ignore
                tuple.block_timestamp,  # type: ignore
                tuple.sig_id,  # type: ignore
            )
            edges.append([r_nodes[tuple.r], key_nodes[tuple.pubkey], sig])

        for tuple in cracked_keys_df.itertuples():
            key_node = key_nodes[tuple.pubkey]
            key_node.set_cracked(
                tuple.privkey,
                tuple.vulnerability_source,
                tuple.lineage,
                tuple.vulnerable_timestamp,
            )
            self._propagating_nodes.add(key_node)

        for tuple in known_nonces_df.itertuples():
            r_node = r_nodes[tuple.r]
            r_node.set_cracked(
                tuple.nonce,
                tuple.vulnerability_source,
                tuple.lineage,
                tuple.vulnerable_timestamp,
            )
            self._propagating_nodes.add(r_node)

        for edge in edges:
            r_node, key_node, sig = edge
            self.G.add_edge(
                r_node,
                key_node,
                sig=sig,
            )

    def __post_checking(
        self,
        cracked_keys_df: pd.DataFrame,
        known_nonces_df: pd.DataFrame,
        uncracked_keys_df: pd.DataFrame,
    ):
        cracked_r_cnt, cracked_key_cnt = 0, 0
        for n in self.G:
            if type(n) == KeyNode and n.cracked:
                cracked_key_cnt += 1
            if type(n) == RNode and n.cracked:
                cracked_r_cnt += 1
        assert cracked_r_cnt == known_nonces_df["r"].nunique()
        assert cracked_key_cnt == cracked_keys_df["pubkey"].nunique()
