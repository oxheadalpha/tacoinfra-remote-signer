import logging
import threading

from pytezos.crypto.encoding import base58_encode
from werkzeug.exceptions import abort

from src.asn1 import HIGH_S_VALUE, Decoder
from src.file_ratchet import FileRatchet

valid_req_types = ["Baking", "Endorsement", "Preendorsement", "Ballot"]


class KmsSigner:
    def __init__(
        self,
        kms_client,
        ratchet=None,
    ):
        self.kms_client = kms_client
        self.ratchet = ratchet
        self.locks = {}

    def sign(self, sigreq, key, key_hash):
        """Entrypoint function for the KmsSigner to sign an operation"""
        op_type = sigreq.get_type()
        if op_type not in valid_req_types:
            raise Exception(f"Unsupported signature request type: {op_type}")

        with self._get_lock(key_hash):
            ratchet_data = {}
            should_validate = self.ratchet and op_type != "Ballot"

            if should_validate:
                ratchet_data = self._validate_op(sigreq, key_hash)

            kms_der_sig = self._kms_sign(sigreq, key)
            decoded_sig = self._decode_sig(kms_der_sig)
            b58_sig = base58_encode(decoded_sig, b"spsig")
            logging.debug(f"Base58-encoded signature: {b58_sig}")

            if should_validate:
                self.ratchet.update(ratchet_data, sigreq,  key_hash)

            return b58_sig.decode("utf-8")

    def _get_lock(self, key_hash):
        """Get or create the lock for the corresponding key_hash"""
        return self.locks.setdefault(key_hash, threading.Lock())

    def _validate_op(self, sigreq, key_hash):
        """Use a ratchet to validate an operation"""
        block_level = sigreq.get_level()
        block_round = sigreq.get_round()
        op_type = sigreq.get_type()

        (is_valid_op, ratchet_data) = self.ratchet.check(sigreq, key_hash)
        if not is_valid_op:
            (lastlevel, lastround) = self._get_last_level_round(ratchet_data[op_type])
            abort(
                410,
                f"Signer for key '{key_hash}' will not sign {op_type}"
                + f" op level/round {block_level}/{block_round}"
                + f" because ratchet has seen {lastlevel}/{lastround}.",
            )
        return ratchet_data

    def _get_last_level_round(self, ratchet_data):
        """Get lastlevel/lastround from FileRatchet or ChainRatchet depending
        upon which type is being used.
        """
        if isinstance(self.ratchet, FileRatchet):
            return (ratchet_data.get("lastlevel"), ratchet_data.get("lastround"))
        else:
            return (self.ratchet.lastlevel, self.ratchet.lastround)

    def _kms_sign(self, sigreq, key):
        """Send the operation to KMS to be signed"""
        key_id = key["key_id"]
        logging.debug(f"Signing with KMS client:")
        logging.debug(f"    Public Key = {key['public_key']}")
        logging.debug(f"    Key ID = {key_id}")

        hashed_data = sigreq.get_blake2bHash()
        logging.debug(f"Hashed data to sign: {hashed_data}")

        sign_result = self.kms_client.sign(
            KeyId=key_id,
            Message=hashed_data,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        der_sig = sign_result["Signature"]
        logging.debug(f"DER encoded signature: {der_sig}")
        return der_sig

    def _decode_sig(self, sig):
        """Decode the ASN1 encoded KMS signature"""
        dec = Decoder()
        dec.start(sig)
        dec.enter()
        _, R = dec.read()
        _, S = dec.read()
        logging.debug(f"R: {R}\nS: {S}")

        if S > HIGH_S_VALUE / 2:
            S = HIGH_S_VALUE - S
            logging.debug(f"Inverting S value to lower form: {S}")

        R_bytes = R.to_bytes(32, "big")
        S_bytes = S.to_bytes(32, "big")
        logging.debug(f"R bytes: {R_bytes}\nS: bytes {S_bytes}")

        sig = R_bytes + S_bytes
        logging.debug("Signature:", sig)
        return sig
