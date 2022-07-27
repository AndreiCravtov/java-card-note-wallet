class Transaction:
    N: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    VERSION: bytes = bytes([0x01, 0x00, 0x00, 0x00])
    NUMBER_OF_INPUTS: bytes = bytes([0x01])

    SEQUENCE: bytes = bytes([0xff, 0xff, 0xff, 0xff])
    NUMBER_OF_OUTPUTS: bytes = bytes([0x01])

    LOCKTIME: bytes = bytes([0x00, 0x00, 0x00, 0x00])
    SIGHASH_CODE: bytes= bytes([0x01, 0x00, 0x00, 0x00])