from dataclasses import dataclass


@dataclass
class CardState:
    is_secure: bool = False
    uncompressed_public_key: bytes = b''
    compressed_public_key: bytes = b''
    p2pkh_address: str = ''
    balance: float = 0

@dataclass
class UTXOData:
    found: bool = False
    txid: str = ''
    vout: int = 0
    value: int = 0
    script_pub_key: str = ''