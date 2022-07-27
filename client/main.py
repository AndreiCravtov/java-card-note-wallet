import base58
import requests
import json
import os
import binascii
from ecdsa import util, VerifyingKey, SECP256k1
from cryptos import Bitcoin
from Crypto.Hash import SHA256, SHA512

from src import *

card_state: CardState = CardState()
utxo_data: UTXOData = UTXOData()

def get_utxo_data(address: str) -> UTXOData:
    utxo_data: UTXOData = UTXOData()
    
    data: str = requests.get(f'https://blockstream.info/testnet/api/address/{address}/utxo').text
    first_json_data: list = json.loads(data)
    if first_json_data == []: return utxo_data

    utxo_data.found = True
    utxo_data.txid = first_json_data[0]['txid']
    utxo_data.vout = first_json_data[0]['vout']
    utxo_data.value = first_json_data[0]['value']

    data = requests.get(f'https://blockstream.info/testnet/api/tx/{utxo_data.txid}').text
    second_json_data: dict = json.loads(data)
                
    utxo_data.script_pub_key = second_json_data['vout'][utxo_data.vout]['scriptpubkey']
    return utxo_data
 
def connect_to_card() -> None:
    # select the applet
    if not APDU.select_applet(): raise Exception("Failed to connect to card...")
    print("Connected to card")

def establish_card_security() -> None:
    global card_state

    apdu: APDU = APDU(APDU.get_apdu_bytes_from_string('B004000001'))
    data: str = APDU.get_apdu_string_from_bytes(apdu.get_response_data())
    if data == '00':
        card_state.is_secure = False
    else:
        card_state.is_secure = True

def get_wallet_balance() -> None:
    global card_state, utxo_data

    # get uncompressed public key
    apdu: APDU = APDU(APDU.get_apdu_bytes_from_string('B000000041'))
    card_state.uncompressed_public_key = bytes(apdu.get_response_data())

    # get compressed public key
    apdu = APDU(APDU.get_apdu_bytes_from_string('B000010021'))
    card_state.compressed_public_key = bytes(apdu.get_response_data())

    # get p2pkh address
    apdu = APDU(APDU.get_apdu_bytes_from_string('B001000019'))
    card_state.p2pkh_address = base58.b58encode(bytes(apdu.get_response_data())).decode()

    # get address balance
    utxo_data = get_utxo_data(card_state.p2pkh_address)
    card_state.balance = utxo_data.value/100000000

def verify_address_ownership() -> None:
    global card_state

    # verify that the address is derrived from the public key correctly
    if card_state.p2pkh_address != Bitcoin(testnet=True).pubtoaddr(APDU.get_apdu_string_from_bytes(list(card_state.compressed_public_key))):
        raise Exception("Address doesn't belong to the public key...")

    # verify that the card owns the public key
    nonce: bytes = os.urandom(32)
    apdu: APDU = APDU([0xB0, 0x02, 0x00, 0x00, 0x20]+list(nonce)+[0x48])
    nonce_signature: bytes = bytes(apdu.get_response_data())
    sha512 = SHA512.new(data=nonce)
    sha256 = SHA256.new(data=sha512.digest())
    nonce_hash: bytes = sha256.digest()
    verifying_key = VerifyingKey.from_string(card_state.uncompressed_public_key, curve=SECP256k1)
    try:
        verified = verifying_key.verify_digest(signature=nonce_signature, digest=nonce_hash, sigdecode=util.sigdecode_der)  # type: ignore
        if not verified: raise Exception()
    except: raise Exception("Public key doesn't belong to card...")

def spend_note() -> None:
    global card_state, utxo_data

    # update utxo data
    utxo_data = get_utxo_data(card_state.p2pkh_address)
    if utxo_data.value == 0:
        print("\nBalance is empty. Please top up first")
        return

    # get recepient address
    print("\nEnter the receiver address")
    while True:
        try:
            receiver_address: bytes = input('> ').encode()
            receiver_address = base58.b58decode_check(receiver_address)[1:]
            if len(receiver_address) == 20: break
        except: pass

    # set input tx_hash and tx_id with correct network byte order
    previous_tx_hash: bytes = bytes(bytearray(binascii.unhexlify(utxo_data.txid))[::-1])
    previous_output_index: bytes = utxo_data.vout.to_bytes(4, byteorder='little')

    # enter fee value and set out value
    print("\nEnter the fee you'd like to pay (in sat)")
    print("The standard fee is 192 sat")
    while True:
        try:
            fee: int = int(input('> '))
            if fee > 0 and fee <= utxo_data.value: break
        except: pass
    value: bytes = int(utxo_data.value-fee).to_bytes(8, byteorder='little')

    # set scriptpubkey and its length
    script_pub_key: bytes = b'v\xa9\x14'+receiver_address+b'\x88\xac'
    script_pub_key_length: bytes = len(script_pub_key).to_bytes(1, byteorder='little')

    # set temporary sigscript and its length
    script_sig: bytes = binascii.unhexlify(utxo_data.script_pub_key)
    script_sig_length: bytes = len(script_sig).to_bytes(1, byteorder='little')

    # create a signing message template
    signing_message_template: bytes = Transaction.VERSION + Transaction.NUMBER_OF_INPUTS + previous_tx_hash + previous_output_index + script_sig_length + script_sig + Transaction.SEQUENCE + Transaction.NUMBER_OF_OUTPUTS + value + script_pub_key_length + script_pub_key + Transaction.LOCKTIME + Transaction.SIGHASH_CODE

    # get the signature from the card
    apdu: APDU = APDU([0xB0, 0x03, 0x00, 0x00]+[len(signing_message_template)]+list(signing_message_template)+[0x48])
    signature_bytes: bytes = bytes(apdu.get_response_data())

    # reduce the s-value in the signature to be within the acceptable range
    offset: int = 4 + int(signature_bytes[3]) + 2 # find where in the signature the s-value starts
    s_value_bytes: bytes = signature_bytes[offset:] # extract the s-value from the signature
    s_value: int = int.from_bytes(s_value_bytes, byteorder='big') # get s-value as an integer
    while s_value > Transaction.N/2: # reduce the s-value
        s_value = (-s_value)%Transaction.N
    s_value_bytes = s_value.to_bytes(32, byteorder='big') # get reduced value as bytes
    signature_bytes = signature_bytes[2:offset-1]+bytes([0x20])+s_value_bytes # reconstruct the signature with reduced s-value
    signature_bytes = bytes([0x30])+bytes([len(signature_bytes)])+signature_bytes

    # create real script_sig and its length
    # add sighash code to signature and prepend length byte and add compressed public key and it's length
    signature_sighash_code = signature_bytes+bytes([0x01])
    script_sig = bytes([len(signature_sighash_code)])+signature_sighash_code+bytes([len(card_state.compressed_public_key)])+card_state.compressed_public_key
    script_sig_length = bytes([len(script_sig)])

    # create final transaction
    final_transaction: bytes = Transaction.VERSION + Transaction.NUMBER_OF_INPUTS + previous_tx_hash + previous_output_index + script_sig_length + script_sig + Transaction.SEQUENCE + Transaction.NUMBER_OF_OUTPUTS + value + script_pub_key_length + script_pub_key + Transaction.LOCKTIME
    transaction_hex: str = binascii.hexlify(final_transaction).decode('utf-8')

    establish_card_security()

    txid: str = requests.post(f'https://blockstream.info/testnet/api/tx', transaction_hex).text
    print("\nCard successfuly spent")
    print(f"The pending transaction ID is {txid}")

    get_wallet_balance()
    

def reset_card() -> None:
    apdu: APDU = APDU(APDU.get_apdu_bytes_from_string('B005000000'))
    if APDU.get_apdu_string_from_bytes(apdu.get_response_sw()) != '9000': raise Exception("Reset failed...")
    print("\nReset complete")
    establish_card_security(); print("Card security retrieved")
    get_wallet_balance(); print(f"Obtained address balance")
    verify_address_ownership(); print("Address belongs to the public key\nPublic key belongs to card")

def display_main_menu() -> None:
    global card_state

    print(f'\nInfo:\n\tCard: {"is" if (card_state.is_secure) else "is NOT"} secure\n\tUncompressed public key: {card_state.uncompressed_public_key.hex().upper()}\n\tCompressed public key: {card_state.compressed_public_key.hex().upper()}\n\tAddress: {card_state.p2pkh_address}\n\tConfirmed balance: {card_state.balance} BTC\n\nMain Menu:\n\t1) Quit\n\t2) Spend note\n\t3) Reset card\n\nPick an option')

def main()-> None:
    global card_state, utxo_data

    connect_to_card()
    establish_card_security(); print("Card security retrieved")
    get_wallet_balance(); print(f"Obtained address balance")
    verify_address_ownership(); print("Address belongs to the public key\nPublic key belongs to card")

    print("\nWelcome to Sterling Notes")
    while True:
        display_main_menu()

        # get choice
        while True:
            try:
                choice: int = int(input('> '))
                if choice in range(1, 4): break
            except: pass
        
        if choice == 1:
            break
        elif choice == 2:
            spend_note()
        elif choice == 3:
            reset_card()

if __name__ == "__main__":
    main()
