import pandas as pd


class Sig:
    def __init__(
        self,
        pubkey: str,
        r: int,
        s: int,
        h: int,
        timestamp: pd.Timestamp,
        sig_id: str,
    ) -> None:
        self.pubkey = pubkey
        self.r = r
        self.s = s
        self.h = h
        self.primary_key = r
        self.timestamp = timestamp
        self.sig_id = sig_id

        self.cracked = False
