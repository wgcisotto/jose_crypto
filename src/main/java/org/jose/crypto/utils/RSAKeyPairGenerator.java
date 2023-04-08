package org.jose.crypto.utils;

import org.jose.crypto.exception.CryptoException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Generates a public/private key pair
 */
public class RSAKeyPairGenerator {

    private static final String KEY_PAIR_GENERATION_ALGORITHM = "RSA";

    private final KeyFactory keyFactory;

    public RSAKeyPairGenerator() {
        try {
            keyFactory = KeyFactory.getInstance(KEY_PAIR_GENERATION_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("All JVMs are required to support the RSA algorithm", e);
        }
    }

    public PublicKey getPublicKeyFromBase64String(String publicKeyBase64String) throws CryptoException {
        Base64.Decoder base64Decoder = Base64.getDecoder();
        final byte[] publicKeyDecoded = base64Decoder.decode(publicKeyBase64String);
        final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyDecoded);
        try {
            return keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException("Failed to generate public key", e);
        }
    }

    public PrivateKey getPrivateKeyFromBase64String(String privateKeyBase64String) throws CryptoException {
        Base64.Decoder base64Decoder = Base64.getDecoder();
        final byte[] privateKeyDecoded = base64Decoder.decode(privateKeyBase64String);
        final PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyDecoded);
        try {
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException("Failed to generate private key", e);
        }
    }



}
