package org.jose.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.jose.crypto.exception.CryptoException;
import org.jose.crypto.model.FlattenedEncrypt;
import org.jose.crypto.model.FlattenedSignature;
import org.jose.crypto.service.JWEAsymmetricCryptoService;
import org.jose.crypto.service.JWEAsymmetricCryptoServiceImpl;
import org.jose.crypto.service.JWSSignatureService;
import org.jose.crypto.service.JWSSignatureServiceImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;

import static org.jose.crypto.utils.KeyUtils.getPrivateKey;
import static org.jose.crypto.utils.KeyUtils.getPublicKey;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
public class EncryptionTest {

    private static final String payload = "{\"name\": \"ActivoBank CC PT\",\"amount\": 200.00,\"currency\": \"EUR\", \"delete\": true}";

    private static final JWSSignatureService jws = new JWSSignatureServiceImpl();

    private static final JWEAsymmetricCryptoService cipher = new JWEAsymmetricCryptoServiceImpl();

    @Test
    public void fullTest() throws CryptoException, NoSuchAlgorithmException, JsonProcessingException, ParseException {
        PrivateKey privateKey = getPrivateKey();
        PublicKey publicKey = getPublicKey();
        log.info("Original message: {}", payload);
        FlattenedSignature sign = jws.sign(payload, privateKey);
        log.info("Message signed: {}", sign.toJson());
        FlattenedEncrypt encrypted = cipher.encrypt(sign.toJson(), publicKey);
        log.info("Message signed and encrypted: {}", encrypted.toJson());
        String decrypted = cipher.decrypt(encrypted, privateKey);
        log.info("Message Decrypted and signed: {}", decrypted);
        String deSigned = jws.deSign(decrypted, publicKey);
        log.info("Message Designed: {}", deSigned);
        assertEquals(payload, deSigned);
    }

}
