from hashlib import blake2b
import struct
import string

from pytezos.crypto.encoding import base58_encode

def get_be_int(bytes):
    return struct.unpack('>L', bytes[0:4])[0]

CHAIN_ID = get_be_int(b'\x00\x57\x52\x00')

class SignatureReq:
    def __init__(self, hexdata):
        if not all(c in string.hexdigits for c in hexdata):
            raise Exception('Invalid signature request: not all hex digits')

        self.level = None
        self.payload = hexdata
        self.data = bytes.fromhex(hexdata)

        self.chainid = base58_encode(self.data[1:5], prefix=b'Net').decode()

        if self.data[0] == 0x03:
            self.type  = "Unknown operation"
            self.level = self.round = 0

        if self.data[0] == 0x01:     # Emmy block
            self.type  = "Baking"
            self.level = get_be_int(self.data[5:])
            self.round = 0

        elif self.data[0] == 0x02:   # Emmy endorsement
            self.type  = "Endorsement"
            self.level = get_be_int(self.data[-4:])
            self.round = 0

        elif self.data[0] == 0x11:   # Tenderbake block
            self.type  = "Baking"
            self.level = get_be_int(self.data[5:])
            fitness_sz = get_be_int(self.data[83:])
            offset = 87 + fitness_sz - 4
            self.round = get_be_int(self.data[offset:])

        elif self.data[0] == 0x12:   # Tenderbake preendorsement
            self.type  = "Preendorsement"
            self.level = get_be_int(self.data[40:])
            self.round = get_be_int(self.data[44:])

        elif self.data[0] == 0x13:   # Tenderbake endorsement
            self.type  = "Endorsement"
            self.level = get_be_int(self.data[40:])
            self.round = get_be_int(self.data[44:])

        else:
            self.type = "Unknown operation"

        self.logstr = f"{self.chainid} {self.type}"
        if self.level != None:
            self.logstr += f" at {self.level}/{self.round}"

    def get_blake2bHash(self, digest_size=32):
      return blake2b(self.data, digest_size=digest_size).digest()

    def get_payload(self):
        return self.payload

    def get_type(self):
        return self.type

    def get_chainid(self):
        return self.chainid

    def get_level(self):
        return self.level

    def get_round(self):
        return self.round

    def get_logstr(self):
        return self.logstr
