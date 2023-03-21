import json
import logging
import os
import threading
from pathlib import Path


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
