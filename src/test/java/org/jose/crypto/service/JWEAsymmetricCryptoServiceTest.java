package org.jose.crypto.service;

import org.jose.crypto.exception.CryptoException;
import org.jose.crypto.model.FlattenedEncrypt;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.jose.crypto.utils.KeyUtils.getPrivateKey;
import static org.jose.crypto.utils.KeyUtils.getPublicKey;
import static org.junit.jupiter.api.Assertions.*;

class JWEAsymmetricCryptoServiceTest {

    private static final JWEAsymmetricCryptoService cipher = new JWEAsymmetricCryptoServiceImpl();

    private static final String payload = "{\"name\": \"ActivoBank CC PT\",\"amount\": 200.00,\"currency\": \"EUR\", \"delete\": true}";

    @Test
    void encrypt() throws CryptoException, NoSuchAlgorithmException {
        PublicKey publicKey = getPublicKey();
        FlattenedEncrypt encrypted = cipher.encrypt(payload, publicKey);
        assertNotNull(encrypted);
        assertNotNull(encrypted.getEncryptedKey());
        assertNotNull(encrypted.getCiphertext());
        assertNotNull(encrypted.getIv());
        assertNotNull(encrypted.getProtectedData());
        assertNotNull(encrypted.getTag());
    }

    @Test
    void encrypt_invalidData() throws CryptoException, NoSuchAlgorithmException {
        PublicKey publicKey = getPublicKey();
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(null, publicKey));
    }

    @Test
    void decrypt() throws CryptoException {
        PrivateKey privateKey = getPrivateKey();
        FlattenedEncrypt flattenedEncrypt = FlattenedEncrypt.builder()
                .protectedData("eyJ4NXQjUzI1NiI6ImtEbnpvZmdSZHhqQ2ZyNENiNFVTQ2dNdXRXZWR2Vy14SmNBZHlVTWwzSGciLCJ0eXAiOiJKT1NFK0pTT04iLCJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0")
                .encryptedKey("ulaEO3_gAKMoH_wStICSABQZf4AZBX2H0jbwX6isgBezb_rvRfeD_9YO_2-GMzkq2hxR_2BbykbVW43sB7AQLqjmmA_uFAJc0Xc3DellxOiwzXxSC-1qPLRWWWUQVI1USXmXfN7xXFKbapZwSzgGkSXmhQDeM_pVHqvPL-Ub53Ix89ord-Gsel7Byhyj9DgjZxiyms6FbP7fZPlegRshnKrKEyeMM_Ogw1OXPEPkmd1ZYPjtXMLoJS5amUQHZ1D4LeA4hmEA_RBCR60F2v2R-kJG-Jx8frVJhp4EEcz7xEdtKOTs93sI6LLr5wANbaJGZvtHqweq7_v2wXiJGhp5Hg")
                .iv("lS3DT7rSPNeK8Hyt")
                .ciphertext("I578tT1l69QffNnzUt4S-D4S_ANJ0QBAgv8rpIpv4M6Hv6Sl79Ta49wBv3fBr8vN4eJAiIcXHB2OIhfxd_4RtnMgxTKnYlsp2hED--iv9w")
                .tag("6ZCqNUI5OC27G2o-Fnf_LA")
                .build();
        String decrypted = cipher.decrypt(flattenedEncrypt, privateKey);
        assertEquals(payload, decrypted);
    }

    @Test
    void decrypt_invalidData() throws CryptoException {
        PrivateKey privateKey = getPrivateKey();
        FlattenedEncrypt flattenedEncrypt = FlattenedEncrypt.builder()
                .protectedData("null")
                .encryptedKey("null-GMzkq2hxR_2BbykbVW43sB7AQLqjmmA_uFAJc0Xc3DellxOiwzXxSC-1qPLRWWWUQVI1USXmXfN7xXFKbapZwSzgGkSXmhQDeM_pVHqvPL-Ub53Ix89ord-Gsel7Byhyj9DgjZxiyms6FbP7fZPlegRshnKrKEyeMM_Ogw1OXPEPkmd1ZYPjtXMLoJS5amUQHZ1D4LeA4hmEA_RBCR60F2v2R-kJG-Jx8frVJhp4EEcz7xEdtKOTs93sI6LLr5wANbaJGZvtHqweq7_v2wXiJGhp5Hg")
                .iv("null")
                .ciphertext("null-D4S_ANJ0QBAgv8rpIpv4M6Hv6Sl79Ta49wBv3fBr8vN4eJAiIcXHB2OIhfxd_4RtnMgxTKnYlsp2hED--iv9w")
                .tag("null-Fnf_LA")
                .build();
        assertThrows(CryptoException.class, () -> cipher.decrypt(flattenedEncrypt, privateKey));
    }

}