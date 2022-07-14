/*
 * Sterling Notes Applet Version 1
 * Andrei Cravtov
 */

package com.enclavehs.sterlingnotes;

import javacard.framework.*;
import javacard.security.*;

/**
 * Sterling Notes Applet class
 * 
 * @author Andrei Cravtov
 */
public class SterlingNotes extends Applet implements AppletEvent {

	// CONSTANTS
	// cla byte
	private static final byte CLA_BYTE = (byte) 0xB0;

	// ins bytes
 	private static final byte INS_GET_PUBLIC_KEY = (byte) 0x00;
	private static final byte INS_GET_ADDRESS_BYTES = (byte) 0x01;
	private static final byte INS_PROVE_OWNERSHIP = (byte) 0x02;
	private static final byte INS_SIGN_TRANSACTION = (byte) 0x03;
	private static final byte INS_GET_SECURITY_STATUS = (byte) 0x04;
	private static final byte INS_RESET_WALLET = (byte) 0x05;

	private static final byte RANDOM_NONCE_SIZE = (byte) 0x20;

	// APPLET LIFE CYCLE VARIABLES
	// field set to true after uninstall
	private boolean disableApp = false;

	// UTILITY VARIABLES
	private byte[] scratch;
	private RandomData randomData;
	private MessageDigest SHA256;
	private MessageDigest SHA512;
	private Signature ECDSA;
	private KeyAgreement scalarMultiplication;
	private ECPrivateKey tempPrivateKey;
	private ECPublicKey tempPublicKey;
	public byte[] privateKey;
	public byte[] uncompressedPublicKey;
	public byte[] compressedPublicKey;
	public byte[] addressBytes;
	public boolean walletIsSecure;
 	
	/**
     * Installs this applet.
     * 
     * @param bArray
     * the array containing installation parameters
     * 
     * @param bOffset
     * the starting offset in bArray
     * 
     * @param bLength
     * the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new SterlingNotes(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
	private SterlingNotes(byte[] bArray, short bOffset, byte bLength) {
		// initialize large scratch to be used within the applet (256 bytes)
		scratch = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

		// INITIALIZE UTILITY VARIABLES
		// randomness
		randomData = RandomData.getInstance(RandomData.ALG_TRNG); // use: randomData.nextBytes(buffer, offset, length)

		// hash
		SHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false); // use: SHA256.doFinal(bufferInput, bufferInputOffset, length, bufferOutput, bufferOutputOffset);
		SHA512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false); // use: SHA512.doFinal(bufferInput, bufferInputOffset, length, bufferOutput, bufferOutputOffset);

		// elliptic curve operations
		ECDSA = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		scalarMultiplication = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
		tempPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, EllipticCurveCrypto.KEY_LENGTH, false);
		tempPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, EllipticCurveCrypto.KEY_LENGTH, false);
		EllipticCurveCrypto.setCurveParameters(tempPrivateKey, tempPublicKey);

		// INITIALIZE WALLET VARIABLES
		// key info
		privateKey = new byte[EllipticCurveCrypto.SCALAR_SIZE];
		uncompressedPublicKey = new byte[EllipticCurveCrypto.UNCOMPRESSED_POINT_SIZE];
		compressedPublicKey = new byte[EllipticCurveCrypto.COMPRESSED_POINT_SIZE];
		addressBytes = new byte[25];

		// wallet status
		walletIsSecure = true;

		// create initial wallet info
		Wallet.generateNewWalletInfo(privateKey, uncompressedPublicKey, compressedPublicKey, addressBytes, scratch, tempPrivateKey, randomData, scalarMultiplication, SHA256);

		// REGISTER APPLET
		register();
    }

	/**
	 * Called by the Java Card runtime environment to inform this applet instance that the Applet Deletion Manager has been requested to delete it.
	 * */
	public void uninstall() {
		if (disableApp) return;

		JCSystem.beginTransaction();  // to protect against tear

		disableApp = true;            // mark as uninstalled

		// cleanup
		randomData = null;
		SHA256 = null;
		SHA512 = null;
		ECDSA = null;
		scalarMultiplication = null;
		tempPrivateKey = null;
		tempPublicKey = null;

		JCSystem.commitTransaction();
	}

    /**
     * Indicates that this applet has been selected.
     */
    public boolean select() {
		return !disableApp; // refuse selection if in uninstalled state
	}
    
    /**
     * Informs the applet that it will be deselected
     * and should perform any clean-up and bookkeeping tasks before the applet is deselected.
     */
    public void deselect() { }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     * the incoming APDU
     */
    public void process(APDU apdu) {
    	
    	// Check if selecting applet APDU
    	if (selectingApplet()) return;
    	
    	// Get the APDU command byte array
    	byte[] buffer = apdu.getBuffer();
    	
    	// Check if and throw exception if the CLA byte doesn't correspond to custom instructions
    	if (buffer[ISO7816.OFFSET_CLA] != CLA_BYTE) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    	
    	// Run appropriate commands based on the instruction byte
		switch (buffer[ISO7816.OFFSET_INS]) {
			case INS_GET_PUBLIC_KEY:
				getPublicKey(apdu);break;
			case INS_GET_ADDRESS_BYTES:
				getAddressBytes(apdu);break;
			case INS_PROVE_OWNERSHIP:
				proveOwnership(apdu);break;
			case INS_SIGN_TRANSACTION:
				signTransaction(apdu);break;
			case INS_GET_SECURITY_STATUS:
				getSecurityStatus(apdu);break;
			case INS_RESET_WALLET:
				resetWallet(apdu);break;
			default:
				// Throw exception if INS byte doesn't match one of the instructions
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
    }

	public void getPublicKey(APDU apdu) {
		/*
		 * Example APDU
		 * b0 00 01 00 21
		 * 02 fa 05 ed 0a 36 49 88 62 70 ba ce c5 dd c1 a3 64 30 09 a7 59 be e9 96 f9 a6 ac 06 0c 99 92 a8 2e 90 00
		 */

		// Gets buffer reference
		byte[] buffer = apdu.getBuffer();

		// return public key
		// P1-byte: 0 -> uncompressed | 1 -> compressed
		short returnLength = 0;
		if (buffer[ISO7816.OFFSET_P1] == (byte) 0) {
			returnLength = EllipticCurveCrypto.UNCOMPRESSED_POINT_SIZE;
			Util.arrayCopy(uncompressedPublicKey, (byte) 0, buffer, (byte) 0, EllipticCurveCrypto.UNCOMPRESSED_POINT_SIZE);
		} else if (buffer[ISO7816.OFFSET_P1] == (byte) 1) {
			returnLength = EllipticCurveCrypto.COMPRESSED_POINT_SIZE;
			Util.arrayCopy(compressedPublicKey, (byte) 0, buffer, (byte) 0, (byte) EllipticCurveCrypto.COMPRESSED_POINT_SIZE);
		} else {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		// set the data transfer direction to outbound
		short le = apdu.setOutgoing();

		// if Le is less than the data we will be returning, throw error
		if (le < returnLength) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// inform the CAD of the actual length of the response data
		apdu.setOutgoingLength(returnLength);

		// send over the reply data
		apdu.sendBytes((short) 0, returnLength);
	}

	public void getAddressBytes(APDU apdu) {
		/*
		 * Example APDU
		 * b0 01 00 00 19
		 * 6f 7a 7c e5 4a 15 87 15 20 fa 94 cf db 75 db ca 8f f7 f2 fb 24 58 a6 b8 98 90 00
		 */

		// Gets buffer reference
		byte[] buffer = apdu.getBuffer();

		// return address bytes
		short returnLength = (short) addressBytes.length;
		Util.arrayCopy(addressBytes, (byte) 0, buffer, (byte) 0, (short) addressBytes.length);

		// set the data transfer direction to outbound
		short le = apdu.setOutgoing();

		// if Le is less than the data we will be returning, throw error
		if (le < returnLength) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// inform the CAD of the actual length of the response data
		apdu.setOutgoingLength(returnLength);

		// send over the reply data
		apdu.sendBytes((short) 0, returnLength);
	}

	public void proveOwnership(APDU apdu) {
		/*
		 * Example APDU [data: 32(nonce)]
		 * b0 02 00 00 20 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 48
		 * 30 46 02 21 00 fa 05 ed 0a 36 49 88 62 70 ba ce c5 dd c1 a3 64 30 09 a7 59 be e9 96 f9 a6 ac 06 0c 99 92 a8 2e 02 21 00 a5 eb 6e 27 a7 5a 08 d6 9b 24 69 23 a7 2d f4 15 02 89 40 dc 62 89 64 62 06 aa ce 14 60 00 af 6d 90 00
		 */

		// Gets buffer reference
		byte[] buffer = apdu.getBuffer();

		// Check if number of bytes received is wrong
		if (buffer[ISO7816.OFFSET_LC] != RANDOM_NONCE_SIZE) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

		// Retrieve data
		apdu.setIncomingAndReceive();

		// sign nonce with key
		short returnLength = EllipticCurveCrypto.sign(privateKey, (byte) 0, buffer, ISO7816.OFFSET_CDATA, RANDOM_NONCE_SIZE, buffer, (short) 0, false, scratch, tempPrivateKey, ECDSA, SHA256, SHA512);

		// set the data transfer direction to outbound
		short le = apdu.setOutgoing();

		// if Le is less than the data we will be returning, throw error
		if (le < returnLength) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// inform the CAD of the actual length of the response data
		apdu.setOutgoingLength(returnLength);

		// send over the reply data
		apdu.sendBytes((short) 0, returnLength);
	}

	public void signTransaction(APDU apdu) {
		/*
		 * Example APDU [data: 114(signing message template)]
		 * b0 03 00 00 72 01 00 00 00 01 e6 34 cc e3 92 2b d5 3f 18 8e 20 ea df fe 92 e9 02 12 4d 73 3d fd 26 d1 ea d1 b5 10 39 ad 00 30 01 00 00 00 19 76 a9 14 76 d7 7a 12 90 d1 d4 62 eb 63 a2 7d c4 12 2f fc b6 9d fd 82 88 ac ff ff ff ff 01 90 5f 01 00 00 00 00 00 19 76 a9 14 ba 27 f9 9e 00 7c 7f 60 5a 83 05 e3 18 c1 ab de 3c d2 20 ac 88 ac 00 00 00 00 01 00 00 00 48
		 * 30 46 02 21 00 fa 05 ed 0a 36 49 88 62 70 ba ce c5 dd c1 a3 64 30 09 a7 59 be e9 96 f9 a6 ac 06 0c 99 92 a8 2e 02 21 00 93 44 22 37 8f c6 bc f9 7a a9 94 09 3c ea ad 06 c5 b3 1d 94 a3 aa 1a b8 42 28 f9 80 a0 25 e4 49 90 00
		 */

		// Gets buffer reference
		byte[] buffer = apdu.getBuffer();

		// Check if number of bytes received is wrong
		if (buffer[ISO7816.OFFSET_LC] < 1) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

		// Retrieve data
		apdu.setIncomingAndReceive();

		// sign nonce with key
		short returnLength = EllipticCurveCrypto.sign(privateKey, (byte) 0, buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC], buffer, (short) 0, true, scratch, tempPrivateKey, ECDSA, SHA256, SHA512);

		// mark wallet as not secure anymore
		walletIsSecure = false;

		// set the data transfer direction to outbound
		short le = apdu.setOutgoing();

		// if Le is less than the data we will be returning, throw error
		if (le < returnLength) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// inform the CAD of the actual length of the response data
		apdu.setOutgoingLength(returnLength);

		// send over the reply data
		apdu.sendBytes((short) 0, returnLength);
	}

	public void getSecurityStatus(APDU apdu) {
		/*
		 * Example APDU
		 * b0 04 00 00 01
		 * 01 90 00
		 */

		// Gets buffer reference
		byte[] buffer = apdu.getBuffer();

		// put wallet security status into buffer
		byte returnLength = (byte) 0x01;
		if (walletIsSecure) {
			buffer[0] = (byte) 0x01;
		} else {
			buffer[0] = (byte) 0x00;
		}

		// set the data transfer direction to outbound
		short le = apdu.setOutgoing();

		// if Le is less than the data we will be returning, throw error
		if (le < returnLength) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		// inform the CAD of the actual length of the response data
		apdu.setOutgoingLength(returnLength);

		// send over the reply data
		apdu.sendBytes((short) 0, returnLength);
	}

	public void resetWallet(APDU apdu) {
		/*
		 * Example APDU
		 * b0 05 00 00 00
		 * 90 00
		 */

		// reset the wallet
		JCSystem.beginTransaction();
		Wallet.generateNewWalletInfo(privateKey, uncompressedPublicKey, compressedPublicKey, addressBytes, scratch, tempPrivateKey, randomData, scalarMultiplication, SHA256);
		walletIsSecure = true;
		JCSystem.commitTransaction();
	}
}
