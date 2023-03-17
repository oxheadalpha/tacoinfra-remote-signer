import json
import logging
import os
import sys
import threading
from pathlib import Path
from random import randint, random
from time import sleep
from typing import Dict

import boto3
from pytezos.crypto.encoding import base58_encode
from werkzeug.exceptions import abort

# sys.path.append(r"/Users/aryehharris/Desktop/roland-remote-signer")
from src.asn1 import Decoder
from src.constants import baking_req_types
from src.signer import Signer

valid_req_types = ["Baking", "Endorsement", "Preendorsement", "Ballot"]


class FileRatchet:
    def __init__(self, ratchets_dir="/etc/file_ratchets", lock=threading.Lock()):
        self.ratchets_dir = Path(ratchets_dir)
        if not self.ratchets_dir.exists:
            raise FileNotFoundError(
                f"File ratchets directory not found: {str(ratchets_dir)}."
            )

        self.ratchet_state = {}
        self._lock = lock

    def get_ratchet_file_path(self, key_hash):
        return self.ratchets_dir / f"{key_hash}.json"

    def get_op_ratchet(self, ratchet_file, op_type):
        ratchet_data = json.load(ratchet_file)
        op_ratchet = ratchet_data.get(op_type)
        return (ratchet_data, op_ratchet)

    def check(self, sigreq, key_hash):
        # if True:
        with self._lock:
            ratchet_file_path = self.get_ratchet_file_path(key_hash)
            block_level = sigreq.get_level()
            block_round = sigreq.get_round()
            op_type = sigreq.get_type()
            # block_level = sigreq["level"]
            # block_round = sigreq["round"]
            # op_type = sigreq["type"]

            # Open or create ratchet file for `key_hash`
            with open(ratchet_file_path, "a+") as ratchet_file:
                new_ratchet_data = {
                    op_type: {
                        "lastlevel": block_level,
                        "lastround": block_round,
                    },
                }

                is_valid_op = True
                # If the ratchet file has data already
                if os.stat(ratchet_file_path).st_size > 0:
                    # Go to beginning of file to read all the data. a+ mode
                    # starts at the end of the file.
                    ratchet_file.seek(0)
                    (ratchet_data, op_ratchet) = self.get_op_ratchet(
                        ratchet_file, op_type
                    )
                    # If the file contains level/round for the op then validate
                    # new level/round.
                    if op_ratchet:
                        lastlevel = op_ratchet["lastlevel"]
                        lastround = op_ratchet["lastround"]
                        logging.info(
                            f"Last {op_type} level/round: {lastlevel}/{lastround}."
                        )
                        is_valid_op = self.validate_op(
                            op_ratchet, block_level, block_round
                        )

                    if is_valid_op:
                        new_ratchet_data = ratchet_data | new_ratchet_data
                    else:
                        self.ratchet_state = ratchet_data

                if is_valid_op:
                    self.update_ratchet(ratchet_file, new_ratchet_data)

            logging.info(f"New {op_type} level/round: {block_level}/{block_round}.")
            logging.debug(f"Is valid operation: {is_valid_op}.")
            return is_valid_op

    def validate_op(self, op_ratchet, block_level, block_round):
        """Validate operation's level/round"""
        lastlevel = op_ratchet["lastlevel"]
        lastround = op_ratchet["lastround"]
        if lastlevel < block_level:
            return True
        if lastlevel == block_level and lastround < block_round:
            return True
        return False

    def update_ratchet(self, ratchet_file, ratchet_data):
        """Update ratchet file and internal state with new level/round"""
        # "a+" mode will append data to `ratchet_file`, so truncate it
        ratchet_file.truncate(0)
        json.dump(ratchet_data, ratchet_file)
        self.ratchet_state = ratchet_data


# TODO we may need to utilize more locking for signing and not just use locks in
# the FileRatchet. If we assume only one baker per  signer, perhaps we don't
# even need a lock in the ratchet if operations come in seqentially from the baker,
# and there is always a sequential response from one op to the next. Even if all
# the ops come in rapid fire, they will all be processed FIFO.
class KmsSigner:
    # class KmsSigner(Signer):
    def __init__(
        self,
        # kms_client=boto3.client(
        #     "kms", region_name=os.environ.get("REGION", "us-east-1")
        # ),
        kms_client,
        # ratchet=FileRatchet(ratchets_dir="./"),
        ratchet=None,
    ):
        self.kms_client = kms_client
        if ratchet:
            self.lock = threading.RLock()
            self.ratchet = ratchet(lock=self.lock)

    def sign(self, sigreq, key, key_hash):
        """Entrypoint function for the KmsSigner to sign an operation"""
        op_type = sigreq.get_type()
        if op_type not in valid_req_types:
            raise Exception(f"Unsupported signature request type: {op_type}")

        if self.ratchet and op_type != "Ballot":
            self._validate_op(sigreq, key_hash)

        kms_der_sig = self._kms_sign(sigreq, key)
        decoded_sig = self._decode_sig(kms_der_sig)
        b58_sig = base58_encode(decoded_sig, b"spsig")
        logging.debug(f"Base58-encoded signature: {b58_sig}")
        return b58_sig.decode("utf-8")

    def _validate_op(self, sigreq, key_hash):
        """Use a ratchet to validate an operation"""
        block_level = sigreq.get_level()
        block_round = sigreq.get_round()
        op_type = sigreq.get_type()
        # block_level = sigreq["level"]
        # block_round = sigreq["round"]
        # op_type = sigreq["type"]

        is_valid_op = self.ratchet.check(sigreq, key_hash)
        if not is_valid_op:
            (lastlevel, lastround) = self._get_last_level_round(op_type)
            abort(
                # print(
                410,
                f"Signer for key '{key_hash}' will not sign {op_type}"
                + f" op level/round {block_level}/{block_round}"
                + f" because ratchet has seen {lastlevel}/{lastround}.",
            )

    def _get_last_level_round(self, op_type):
        """Get lastlevel/lastround from FileRatchet or ChainRatchet depending
        upon which type is being used.
        """
        if isinstance(self.ratchet, FileRatchet):
            ratchet_op_type = self.ratchet.ratchet_state.get(op_type, {})
            return (ratchet_op_type.get("lastlevel"), ratchet_op_type.get("lastround"))
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

        high_s_value = (
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        )
        if S > high_s_value / 2:
            S = high_s_value - S
            logging.debug(f"Inverting S value to lower form: {S}")

        R_bytes = R.to_bytes(32, "big")
        S_bytes = S.to_bytes(32, "big")
        logging.debug(f"R bytes: {R_bytes}\nS: bytes {S_bytes}")

        sig = R_bytes + S_bytes
        logging.debug("Signature:", sig)
        return sig

