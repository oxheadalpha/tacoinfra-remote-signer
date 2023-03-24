import json
import logging
import os
from pathlib import Path

"""
Uses a file as a ratchet, named as the key hash that's performing an operation.
IMPORTANT: The following should all be executed with a `Lock`:
- The `check` method should be run first to validate the operation.
- If the operation is valid then it should be signed for.
- Finally the `update` method should be run to update the ratchet file.
- The lock should then be released.
"""
class FileRatchet:
    def __init__(self, ratchets_dir="/etc/file_ratchets"):
        self.ratchets_dir = Path(ratchets_dir)
        if not self.ratchets_dir.exists:
            raise FileNotFoundError(
                f"File ratchets directory not found: {str(ratchets_dir)}."
            )

    def get_ratchet_file_path(self, key_hash):
        return self.ratchets_dir / f"{key_hash}.json"

    def get_op_ratchet(self, ratchet_file, op_type):
        ratchet_data = json.load(ratchet_file)
        op_ratchet = ratchet_data.get(op_type)
        return (ratchet_data, op_ratchet)

    def validate_op(self, op_ratchet, block_level, block_round):
        """Validate operation's level/round"""
        lastlevel = op_ratchet["lastlevel"]
        lastround = op_ratchet["lastround"]
        if lastlevel < block_level:
            return True
        if lastlevel == block_level and lastround < block_round:
            return True
        return False

    def update(self, ratchet_data, sigreq, key_hash):
        """Update ratchet file and internal state with new level/round"""
        ratchet_file_path = self.get_ratchet_file_path(key_hash)
        ratchet_state = ratchet_data | {
            sigreq.get_type(): {
                "lastlevel": sigreq.get_level(),
                "lastround": sigreq.get_round(),
            }
        }

        with open(ratchet_file_path, "w") as ratchet_file:
            json.dump(ratchet_state, ratchet_file)

    def check(self, sigreq, key_hash):
        ratchet_file_path = self.get_ratchet_file_path(key_hash)
        block_level = sigreq.get_level()
        block_round = sigreq.get_round()
        op_type = sigreq.get_type()
        # block_level = sigreq["level"]
        # block_round = sigreq["round"]
        # op_type = sigreq["type"]

        is_valid_op = True
        ratchet_data = {}
        # Open or create ratchet file for `key_hash`
        with open(ratchet_file_path, "a+") as ratchet_file:
            # If the ratchet file has data already
            if os.stat(ratchet_file_path).st_size > 0:
                # Go to beginning of file to read all the data. a+ mode
                # starts at the end of the file.
                ratchet_file.seek(0)
                (read_ratchet_data, op_ratchet) = self.get_op_ratchet(
                    ratchet_file, op_type
                )
                ratchet_data = read_ratchet_data
                # If the file contains level/round for the op then validate
                # new level/round.
                if op_ratchet:
                    lastlevel = op_ratchet["lastlevel"]
                    lastround = op_ratchet["lastround"]
                    logging.info(
                        f"{key_hash}: Last {op_type} level/round: {lastlevel}/{lastround}."
                    )
                    is_valid_op = self.validate_op(op_ratchet, block_level, block_round)

        logging.info(
            f"{key_hash}: New {op_type} level/round: {block_level}/{block_round}."
        )
        logging.debug(f"Is valid operation: {is_valid_op}.")
        return (is_valid_op, ratchet_data)
