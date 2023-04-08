package org.jose.crypto.utils;

import org.jose.crypto.exception.CryptoException;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;

import static org.jose.crypto.utils.KeyUtils.*;
import static org.junit.jupiter.api.Assertions.*;

class RSAKeyPairGeneratorTest {

    @Test
    void testGetPublicKeyFromBase64String() throws CryptoException {
        PublicKey publicKeyFromBase64String = getPublicKey();
        assertNotNull(publicKeyFromBase64String);
    }

    @Test
    void testGetPrivateKeyFromBase64String() throws CryptoException {
        PrivateKey privateKeyFromBase64String = getPrivateKey();
        assertNotNull(privateKeyFromBase64String);
    }

    @Test
    void testGetPublicKeyFromInvalidString() throws CryptoException {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        assertThrows(CryptoException.class, ()-> keyPairGenerator.getPublicKeyFromBase64String(""));
    }

    @Test
    void testGetPrivateKeyFromInvalidString() {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        assertThrows(CryptoException.class, ()-> keyPairGenerator.getPrivateKeyFromBase64String(""));
    }
}