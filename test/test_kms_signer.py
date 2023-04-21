import json
import os
import shutil
import unittest
import unittest.mock
from unittest.mock import Mock

from src.asn1 import HIGH_S_VALUE, Decoder
from src.file_ratchet import FileRatchet
from src.kms_signer import KmsSigner


def asn1_decode_kms_sig_R_S(sig):
    decoder = Decoder()
    decoder.start(sig)
    decoder.enter()
    _, R = decoder.read()
    _, S = decoder.read()
    return R, S


def get_decoded_kms_sig(R, S):
    R_bytes = R.to_bytes(32, "big")
    S_bytes = S.to_bytes(32, "big")
    return R_bytes + S_bytes


operation_types = ["Baking", "Endorsement", "Preendorsement"]
key = {"key_id": "test_key_id", "public_key": "test_public_key"}
key_hash = "test_key_hash"


class TestKmsSigner(unittest.TestCase):
    def setUp(self):
        self.mock_kms_client = Mock()
        self.kms_signer = KmsSigner(self.mock_kms_client)

    def test_init(self):
        self.assertEqual(self.kms_signer.kms_client, self.mock_kms_client)

    def test_sign_unsupported_request_type(self):
        sigreq_mock = Mock()
        sigreq_mock.get_type.return_value = "UnsupportedType"

        with self.assertRaises(Exception) as context:
            self.kms_signer.sign(sigreq_mock, key, key_hash)

        self.assertEqual(
            str(context.exception),
            "Unsupported signature request type: UnsupportedType",
        )

    def test_get_correct_lock(self):
        lock1 = self.kms_signer._get_lock(key_hash)
        lock2 = self.kms_signer._get_lock(key_hash)
        self.assertIs(lock1, lock2)

        lock3 = self.kms_signer._get_lock("tz123")
        lock4 = self.kms_signer._get_lock("tz123")
        self.assertIsNot(lock1, lock3)
        self.assertIs(lock3, lock4)

    def test_decode_kms_sig_high_s(self):
        kms_sig = b'0F\x02!\x00\x97B\x05\xe4n\xe6I\xa5\xca:\x9br\xcas#.\xccY\x01\x0c\xbc\xf3\xc9\xee\x8f\xb43\x9d\xa7\x1dh0\x02!\x00\x8f\xee\xaf\x8f5\xaf\x12\xde\xd3\xec\xdfKfGz\xf5rZ\x0eS"\xe2\x91D\xb1G\x08\t\xe1[\xf5\x00'

        R, S = asn1_decode_kms_sig_R_S(kms_sig)
        self.assertGreater(
            S, HIGH_S_VALUE / 2, "S value should be greater than high S value / 2"
        )

        S = HIGH_S_VALUE - S
        decoded_sig = get_decoded_kms_sig(R, S)

        test_decoded_sig = self.kms_signer._decode_sig(kms_sig)
        self.assertEqual(test_decoded_sig, decoded_sig)

    def test_decode_kms_sig_low_s(self):
        kms_sig = b"0E\x02!\x00\xc4\xc5\xb9f\x8aZ\xad\xb3\xd5\xe2\x0f5\xcf\x1c&\xed\xdf\x82P\x04\xf6\x07\xafd=\xe2'\x14K\x1c\xa1\xb2\x02 OX\xb5\x1d\xb6\x085\xdbm|\xdatx[\xd1\xaaN\x07H\x84#O\xbfY\xec\xf5\x84O\xf9F\xad\xe5"

        R, S = asn1_decode_kms_sig_R_S(kms_sig)
        self.assertLess(
            S, HIGH_S_VALUE / 2, "S value should be less than high S value / 2"
        )

        decoded_sig = get_decoded_kms_sig(R, S)

        test_decoded_sig = self.kms_signer._decode_sig(kms_sig)
        self.assertEqual(test_decoded_sig, decoded_sig)


class TestKmsSignerWithFileRatchet(unittest.TestCase):
    def setUp(self):
        self.tempdir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "tmp/TestKmsSignerWithFileRatchet",
        )
        os.makedirs(self.tempdir, exist_ok=True)

        self.mock_kms_client = Mock()
        self.ratchet = FileRatchet(self.tempdir)
        self.kms_signer = KmsSigner(self.mock_kms_client, self.ratchet)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _get_sigreq_for_type(self, op_type, block_level, block_round):
        sigreq = Mock()
        sigreq.get_type.return_value = op_type
        sigreq.get_level.return_value = block_level
        sigreq.get_round.return_value = block_round
        return sigreq

    def _set_ratchet_state(self, op_type, block_level, block_round):
        ratchet_data = {op_type: {"lastlevel": block_level, "lastround": block_round}}
        ratchet_data_sigreq = self._get_sigreq_for_type(
            op_type, block_level, block_round
        )
        self.ratchet.update(ratchet_data, ratchet_data_sigreq, key_hash)

    def test_init(self):
        self.assertEqual(self.kms_signer.kms_client, self.mock_kms_client)
        self.assertEqual(self.kms_signer.ratchet, self.ratchet)

    def test_sign_unsupported_request_type(self):
        sigreq_mock = Mock()
        sigreq_mock.get_type.return_value = "UnsupportedType"
        with self.assertRaises(Exception) as context:
            self.kms_signer.sign(sigreq_mock, key, key_hash)
        self.assertEqual(
            str(context.exception),
            "Unsupported signature request type: UnsupportedType",
        )

    def _test_valid_operation(self, sigreq, prev_level, prev_round):
        self._set_ratchet_state(sigreq.get_type(), prev_level, prev_round)
        try:
            self._test_sign_operation_with_ratchet(sigreq)
        except Exception as e:
            self.fail(
                f"Unexpected exception for valid operation {sigreq.get_type()} at level {sigreq.get_level()} and round {sigreq.get_round()}: {e}"
            )

    def _test_invalid_operation(self, sigreq, prev_level, prev_round):
        self._set_ratchet_state(sigreq.get_type(), prev_level, prev_round)
        with self.assertRaises(Exception):
            self._test_sign_operation_with_ratchet(sigreq)

    def _test_sign_operation_with_ratchet(self, sigreq):
        # Mock KMS client `sign` method
        self.mock_kms_client.sign.return_value = {
            "Signature": b"0E\x02!\x00\xc4\xc5\xb9f\x8aZ\xad\xb3\xd5\xe2\x0f5\xcf\x1c&\xed\xdf\x82P\x04\xf6\x07\xafd=\xe2'\x14K\x1c\xa1\xb2\x02 OX\xb5\x1d\xb6\x085\xdbm|\xdatx[\xd1\xaaN\x07H\x84#O\xbfY\xec\xf5\x84O\xf9F\xad\xe5"
        }

        result = self.kms_signer.sign(sigreq, key, key_hash)

        # Check if the mock sign method was called with correct parameters
        self.mock_kms_client.sign.assert_called_with(
            KeyId="test_key_id",
            Message=sigreq.get_blake2bHash(),
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )

        self.assertIsInstance(result, str)

        # Read the ratchet file and check if the ratchet data is updated
        ratchet_file_path = os.path.join(self.tempdir, f"{key_hash}.json")
        op_type = sigreq.get_type()

        try:
            with open(ratchet_file_path, "r") as f:
                ratchet_data = json.load(f)

            if op_type != "Ballot":
                self.assertIn(op_type, ratchet_data)
                self.assertEqual(ratchet_data[op_type]["lastlevel"], sigreq.get_level())
                self.assertEqual(ratchet_data[op_type]["lastround"], sigreq.get_round())
            else:
                # If the operation type is "Ballot", the ratchet should not update
                self.assertNotIn(op_type, ratchet_data)

        except FileNotFoundError:
            if op_type != "Ballot":
                self.fail("Ratchet file not found for a non-Ballot operation")

    def test_valid_operations(self):
        print("BEGIN: VALID OPS")
        for op_type in operation_types:
            sigreq = self._get_sigreq_for_type(op_type, block_level=1, block_round=0)
            self._test_valid_operation(sigreq, prev_level=0, prev_round=0)

            sigreq = self._get_sigreq_for_type(op_type, block_level=2, block_round=2)
            self._test_valid_operation(sigreq, prev_level=1, prev_round=0)

            sigreq = self._get_sigreq_for_type(op_type, block_level=2, block_round=3)
            self._test_valid_operation(sigreq, prev_level=2, prev_round=2)
        print("END: VALID OPS\n")

    def test_invalid_operations(self):
        print("BEGIN: INVALID OPS")
        for op_type in operation_types:
            sigreq = self._get_sigreq_for_type(op_type, block_level=1, block_round=0)
            self._test_invalid_operation(sigreq, prev_level=1, prev_round=0)

            sigreq = self._get_sigreq_for_type(op_type, block_level=2, block_round=1)
            self._test_invalid_operation(sigreq, prev_level=3, prev_round=2)

            sigreq = self._get_sigreq_for_type(op_type, block_level=5, block_round=3)
            self._test_invalid_operation(sigreq, prev_level=5, prev_round=4)
        print("END: INVALID OPS\n")

    def test_ballot_operation(self):
        sigreq = self._get_sigreq_for_type("Ballot", block_level=None, block_round=None)
        with unittest.mock.patch.object(
            self.ratchet, "update"
        ) as check, unittest.mock.patch.object(self.ratchet, "check") as update:
            try:
                self._test_sign_operation_with_ratchet(sigreq)
            except Exception as e:
                self.fail(f"Unexpected exception for Ballot operation: {e}")
            check.assert_not_called()
            update.assert_not_called()


if __name__ == "__main__":
    unittest.main()
