package com.enclavehs.sterlingnotes;

import javacard.framework.Util;
import javacard.security.*;

public class EllipticCurveCrypto {

    /**
     * Signs variable-length message with private key.<br><br>
     *
     *
     * The algorithm is ECDSA but there are two hash functions available:<br>
     * <b>isTransaction</b> == true -> SHA256(SHA256( data )) for signing Bitcoin transactions<br>
     * <b>isTransaction</b> == false -> SHA256(SHA512( data )) for signing anything other than a transaction<br><br>
     *
     * The number of bytes of the signature is anywhere from 70 to 72 bytes<br>
     * Signature structure:<br>
     * (compound marker)(compound length)<br>
     * &#9;(integer marker)(integer length)<br>
     * &#9;&#9;(padding if needed)(r-value)<br>
     * &#9;(integer marker)(integer length)<br>
     * &#9;&#9;(padding if needed)(r-value)<br>
     *
     * @param privKeyBuff private key bytes buffer
     * @param privKeyBuffOff private key bytes buffer offset
     * @param inBuff data input buffer
     * @param inBuffOff data input buffer offset
     * @param inBuffLength input data length
     * @param outBuff output buffer for signature
     * @param outBuffOff output buffer offset
     * @param isTransaction specifies which hash function to use
     * @param scratch provides a scratch buffer to store intermediate results
     * @param tempPrivateKey provides a temporary private key object reference
     * @param ECDSA provides with an ECDSA algorithm object reference
     * @param SHA256 provides with a SHA256 algorithm object reference
     * @param SHA512 provides with a SHA512 algorithm object reference
     * @return number of bytes in signature
     */
    public static short sign(
            byte[] privKeyBuff, short privKeyBuffOff, byte[] inBuff, short inBuffOff, short inBuffLength, byte[] outBuff, short outBuffOff, boolean isTransaction,
            byte[] scratch, ECPrivateKey tempPrivateKey, Signature ECDSA, MessageDigest SHA256, MessageDigest SHA512
    ) {
        // Set private key and initialise signing algorithm
        tempPrivateKey.setS(privKeyBuff, privKeyBuffOff, SCALAR_SIZE);
        ECDSA.init(tempPrivateKey, Signature.MODE_SIGN);

        if (isTransaction) { // TRANSACTION MODE
            // Hash the input data twice with SHA256: SHA256(SHA256( data ))
            SHA256.doFinal(inBuff, inBuffOff, inBuffLength, scratch, (short) 0);
            SHA256.doFinal(scratch, (short) 0, (short) 0x20, scratch, (short) 0);
        } else { // REGULAR MESSAGE MODE
            // Hash the input data with SHA512 and SHA256: SHA256(SHA512( data ))
            SHA512.doFinal(inBuff, inBuffOff, inBuffLength, scratch, (short) 0);
            SHA256.doFinal(scratch, (short) 0, (byte) 0x40, scratch, (short) 0);
        }

        // Signs the digest in scratch => returns (r,s)
        return ECDSA.signPreComputedHash(scratch, (short) 0, (short) 0x20, outBuff, outBuffOff);
    }

    /**
     * Sets the Secp256k1 curve parameters to the given public and private keys.
     *
     * @param privateKey the public key where the curve parameters must be set
     * @param  publicKey the private key where the curve parameters must be set
     */
    public static void setCurveParameters(ECPrivateKey privateKey, ECPublicKey publicKey) {
        privateKey.setA(a, (short) 0x00, (short) a.length);
        privateKey.setB(b, (short) 0x00, (short) b.length);
        privateKey.setFieldFP(p, (short) 0x00, (short) p.length);
        privateKey.setG(G, (short) 0x00, (short) G.length);
        privateKey.setR(r, (short) 0x00, (short) r.length);
        privateKey.setK(k);

        publicKey.setA(a, (short) 0x00, (short) a.length);
        publicKey.setB(b, (short) 0x00, (short) b.length);
        publicKey.setFieldFP(p, (short) 0x00, (short) p.length);
        publicKey.setG(G, (short) 0x00, (short) G.length);
        publicKey.setR(r, (short) 0x00, (short) r.length);
        publicKey.setK(k);
    }

    /**
     * Derives the public key from the given private key.
     * This is done by multiplying the private key by the G point of the curve.
     *
     * @param privateKey the private key
     * @param privateKeyOff the offset of the private key buffer
     * @param pubOut the output buffer for the public key
     * @param pubOff the offset in pubOut
     * @param tempPrivateKey provides a temporary private key object reference
     * @param scalarMultiplication provides with an ECDH algorithm object reference
     */
    public static void derivePublicKeyFromPrivateKey(
            byte[] privateKey, short privateKeyOff, byte[] pubOut, short pubOff,
            ECPrivateKey tempPrivateKey, KeyAgreement scalarMultiplication
    ) {
        ECPointScalarMultiplication(privateKey, privateKeyOff, G, (short) 0, (short) G.length, pubOut, pubOff, tempPrivateKey, scalarMultiplication);
    }

    /**
     * Multiplies a scalar by an uncompressed EC point.
     * Outputs both X and Y in uncompressed form.
     *
     * @param scalar scalar byte array buffer
     * @param scalarOff the offset of the scalar buffer
     * @param point the point buffer to multiply
     * @param pointOff the offset of the point buffer
     * @param pointLen the length of the point buffer
     * @param out the output buffer
     * @param outOff the offset in the output buffer
     * @param tempPrivateKey provides a temporary private key object reference
     * @param scalarMultiplication provides with an ECDH algorithm object reference
     */
    public static void ECPointScalarMultiplication(
            byte[] scalar, short scalarOff, byte[] point, short pointOff, short pointLen, byte[] out, short outOff,
            ECPrivateKey tempPrivateKey, KeyAgreement scalarMultiplication
    ) {
        // set private key and innit key agreement
        tempPrivateKey.setS(scalar, scalarOff, SCALAR_SIZE);
        scalarMultiplication.init(tempPrivateKey);

        // perform multiplication
        scalarMultiplication.generateSecret(point, pointOff, pointLen, out, outOff);
    }

    /**
     * Turns an uncompressed point (65 bytes) into a compressed point (33 bytes)
     *
     * @param point the point buffer to make compressed
     * @param pointOff the offset of the point buffer
     * @param out the output buffer
     * @param outOff the offset in the output buffer
     */
    public static void uncompressedToCompressedPublicKey(byte[] point, short pointOff, byte[] out, short outOff) {
        // Copy x-coordinate only to output buffer with offset of 1
        Util.arrayCopyNonAtomic(point, (short) (pointOff+1), out, (short) (outOff+1), COORDINATE_SIZE);

        // Write in correct prefix into position 0
        if (point[(byte)(UNCOMPRESSED_POINT_SIZE - 1)] % (byte) 0x02 == (byte) 0x00)
            out[outOff] = (byte) 0x02; // even
        else out[outOff] = (byte) 0x03; //odd
    }

    /*
     * Meta info about Secp256k1
     */
    public static final short KEY_LENGTH = 256; // Bits
    public static final short UNCOMPRESSED_POINT_SIZE = 65; // Bytes
    public static final short COMPRESSED_POINT_SIZE = 33; // Bytes
    public static final short COORDINATE_SIZE = 32; // Bytes
    public static final short SCALAR_SIZE = 32; // Bytes

    /*
     * Secp256k1 domain parameters
     */
    public static final byte[] a = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
    };

    public static final byte[] b = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07
    };

    public static final byte[] p = new byte[]{
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
            (byte) 0xff, (byte) 0xff, (byte) 0xfc, (byte) 0x2f
    };

    public static final byte[] G = new byte[]{
            (byte) 0x04,

            (byte) 0x79, (byte) 0xbe, (byte) 0x66, (byte) 0x7e,
            (byte) 0xf9, (byte) 0xdc, (byte) 0xbb, (byte) 0xac,
            (byte) 0x55, (byte) 0xa0, (byte) 0x62, (byte) 0x95,
            (byte) 0xce, (byte) 0x87, (byte) 0x0b, (byte) 0x07,
            (byte) 0x02, (byte) 0x9b, (byte) 0xfc, (byte) 0xdb,
            (byte) 0x2d, (byte) 0xce, (byte) 0x28, (byte) 0xd9,
            (byte) 0x59, (byte) 0xf2, (byte) 0x81, (byte) 0x5b,
            (byte) 0x16, (byte) 0xf8, (byte) 0x17, (byte) 0x98,

            (byte) 0x48, (byte) 0x3a, (byte) 0xda, (byte) 0x77,
            (byte) 0x26, (byte) 0xa3, (byte) 0xc4, (byte) 0x65,
            (byte) 0x5d, (byte) 0xa4, (byte) 0xfb, (byte) 0xfc,
            (byte) 0x0e, (byte) 0x11, (byte) 0x08, (byte) 0xa8,
            (byte) 0xfd, (byte) 0x17, (byte) 0xb4, (byte) 0x48,
            (byte) 0xa6, (byte) 0x85, (byte) 0x54, (byte) 0x19,
            (byte) 0x9c, (byte) 0x47, (byte) 0xd0, (byte) 0x8f,
            (byte) 0xfb, (byte) 0x10, (byte) 0xd4, (byte) 0xb8
    };

    public static final byte[] r = new byte[]{
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
            (byte) 0xba, (byte) 0xae, (byte) 0xdc, (byte) 0xe6,
            (byte) 0xaf, (byte) 0x48, (byte) 0xa0, (byte) 0x3b,
            (byte) 0xbf, (byte) 0xd2, (byte) 0x5e, (byte) 0x8c,
            (byte) 0xd0, (byte) 0x36, (byte) 0x41, (byte) 0x41,
    };

    public static final byte k = (byte) 0x01;
}