package com.enclavehs.sterlingnotes;

import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class Wallet {
    /**
     * This creates new wallet info
     * @param privateKey private key buffer
     * @param uncompressedPublicKey uncompressed public key buffer
     * @param compressedPublicKey compressed public key buffer
     * @param addressBytes address bytes buffer
     * @param scratch scratch buffer
     * @param tempPrivateKey provides a temporary private key object reference
     * @param randomData provides with a random data generation algorithm object reference
     * @param scalarMultiplication provides with an ECDH algorithm object reference
     * @param SHA256 provides with a SHA256 algorithm object reference
     */
    public static void generateNewWalletInfo(
            byte[] privateKey, byte[] uncompressedPublicKey, byte[] compressedPublicKey, byte[] addressBytes,
            byte[] scratch, ECPrivateKey tempPrivateKey, RandomData randomData, KeyAgreement scalarMultiplication, MessageDigest SHA256
    ) {
        // generate random 32 bytes as the private key
        do {
            randomData.nextBytes(privateKey, (byte) 0, EllipticCurveCrypto.SCALAR_SIZE);
        } while (
                BigInteger.equalZero(privateKey, (byte) 0, EllipticCurveCrypto.SCALAR_SIZE) ||
                !(BigInteger.lessThan(privateKey, (byte) 0, EllipticCurveCrypto.r, (byte) 0, EllipticCurveCrypto.SCALAR_SIZE))
        );

        // generate uncompressed public key from private key
        EllipticCurveCrypto.derivePublicKeyFromPrivateKey(privateKey, (byte) 0, uncompressedPublicKey, (byte) 0, tempPrivateKey, scalarMultiplication);

        // get compressed key from uncompressed key
        EllipticCurveCrypto.uncompressedToCompressedPublicKey(uncompressedPublicKey, (byte) 0, compressedPublicKey, (byte) 0);

        // generate address bytes
        generateAddressBytes(compressedPublicKey, addressBytes, scratch, SHA256);
    }

    /**
     * This generates the 25-byte P2PKH Bitcoin address
     * @param compressedPublicKey compressed public key buffer
     * @param addressBytes address bytes buffer
     * @param scratch scratch buffer
     * @param SHA256 provides with a SHA256 algorithm object reference
     */
    private static void generateAddressBytes(
            byte[] compressedPublicKey, byte[] addressBytes,
            byte[] scratch, MessageDigest SHA256
    ) {
        // hash the compressed public key
        // RIPEMD160( SHA256( compressed public key ) ) -> from scratch[1] to scratch[20]
        SHA256.doFinal(compressedPublicKey, (short) 0, EllipticCurveCrypto.COMPRESSED_POINT_SIZE, scratch, (short) 0);
        RIPEMD160.hash32(scratch, (short) 0, scratch, (short) 1, scratch, (short) 0);

        // prepend version byte to the front
        // version byte at scratch[0]
        scratch[0] = (byte) 0x6f; // this is the bitcoin testnet version byte. the real bitcoin version byte is 0x00

        // calculate checksum -> first 4 bytes of SHA256( SHA256( prefix + hash ) ) and append
        // creates the 25 byte long address
        SHA256.doFinal(scratch, (short) 0, (short) 21, scratch, (short) 21);
        SHA256.doFinal(scratch, (short) 21, (short) 32, scratch, (short) 21);

        // copy over the address bytes from scratch
        javacard.framework.Util.arrayCopy(scratch, (byte) 0, addressBytes, (byte) 0, (byte) 25);
    }
}
