import networkx as nx
from abc import ABC, abstractmethod
from ecdsa_cracker.ecdsa_helper import (
    derive_nonce_from_known_private_key,
    derive_private_key_from_known_nonce,
)
import ecdsa


class Node(ABC):
    def __init__(self, curve: ecdsa.curves.Curve) -> None:
        super().__init__()
        self.primary_key = None
        self.curve = curve

        self.vulnerability_source = None
        self.lineage = None
        self.vulnerable_timestamp = None

        self.cracked = False

    @abstractmethod
    def propagate(self, G: nx.Graph, origin):
        pass

    def set_cracked(
        self,
        data,
        vulnerability_source,
        lineage,
        vulnerable_timestamp,
    ):
        self.cracked = True
        self.vulnerability_source = vulnerability_source
        self.lineage = lineage
        if (
            not self.vulnerable_timestamp
            or vulnerable_timestamp < self.vulnerable_timestamp
        ):
            self.vulnerable_timestamp = vulnerable_timestamp

    def __eq__(self, other) -> bool:
        if type(other) == str or type(other) == int:
            return self.primary_key == other
        return self.primary_key == other.primary_key

    def __hash__(self) -> int:
        return hash(self.primary_key)


class KeyNode(Node):
    def __init__(self, pubkey: str, curve: ecdsa.curves.Curve) -> None:
        super().__init__(curve)
        self.primary_key = pubkey

        self.pubkey = pubkey
        self.privkey = None

    def set_cracked(
        self,
        data,
        vulnerability_source,
        lineage,
        vulnerable_timestamp,
    ):
        super().set_cracked(data, vulnerability_source, lineage, vulnerable_timestamp)
        self.privkey = data

    def propagate(self, G: nx.Graph, origin: "RNode"):
        if not origin.cracked or not origin.vulnerable_timestamp or not origin.nonce:
            raise ValueError(
                f"The origin {origin.primary_key} should be cracked before propagating."
            )

        edge = G[origin][self]["sig"]
        new_ts = max(edge.block_timestamp, origin.vulnerable_timestamp)
        if not self.cracked or new_ts < self.vulnerable_timestamp:
            if not self.cracked:
                privkey = derive_private_key_from_known_nonce(
                    edge.r, edge.s, edge.h, origin.nonce, self.pubkey, curve=self.curve
                )
            else:
                privkey = self.privkey

            self.set_cracked(
                privkey,
                "known_nonce:" + str(origin.primary_key),
                [edge.sig_id],
                new_ts,
            )
            for dst in G.neighbors(self):
                dst.propagate(G, self)


class RNode(Node):
    def __init__(self, r: int, curve: ecdsa.curves.Curve) -> None:
        super().__init__(curve)
        self.primary_key = r

        self.r = r
        self.nonce = None

    def set_cracked(
        self,
        data,
        vulnerability_source,
        lineage,
        vulnerable_timestamp,
    ):
        super().set_cracked(data, vulnerability_source, lineage, vulnerable_timestamp)
        self.nonce = data

    def propagate(self, G: nx.Graph, origin: "KeyNode"):
        if not origin.cracked or not origin.vulnerable_timestamp or not origin.privkey:
            raise ValueError(
                f"The origin {origin.primary_key} should be cracked before propagating."
            )

        edge = G[origin][self]["sig"]
        new_ts = max(edge.block_timestamp, origin.vulnerable_timestamp)
        if not self.cracked or new_ts < self.vulnerable_timestamp:
            if not self.cracked:
                nonce = derive_nonce_from_known_private_key(
                    self.r, edge.s, edge.h, origin.privkey, curve=self.curve
                )
            else:
                nonce = self.nonce
            self.set_cracked(
                nonce,
                "known_private_key:" + str(origin.primary_key),
                [edge.sig_id],
                new_ts,
            )
            for dst in G.neighbors(self):
                dst.propagate(G, self)
