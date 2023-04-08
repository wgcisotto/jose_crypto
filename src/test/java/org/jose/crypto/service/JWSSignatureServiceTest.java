package org.jose.crypto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.jose.crypto.exception.CryptoException;
import org.jose.crypto.model.FlattenedSignature;
import org.jose.crypto.utils.RSAKeyPairGenerator;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;

import static org.jose.crypto.utils.KeyUtils.*;
import static org.junit.jupiter.api.Assertions.*;

class JWSSignatureServiceTest {

    private static final JWSSignatureService jws = new JWSSignatureServiceImpl();
    private static final String payload = "{\"name\": \"ActivoBank CC PT\",\"amount\": 200.00,\"currency\": \"EUR\", \"delete\": true}";
    public static final String payloadSigned = "eyJuYW1lIjogIkFjdGl2b0JhbmsgQ0MgUFQiLCJhbW91bnQiOiAyMDAuMDAsImN1cnJlbmN5IjogIkVVUiIsICJkZWxldGUiOiB0cnVlfQ";
    public static final String protectedData = "eyJ4NXQjUzI1NiI6IlBHYnRYNVdJR0ZZd3NnTGNpWEdiZlVSOWVXZThNc0E3M0Fhay16QW1EbGMiLCJ0eXAiOiJKT1NFK0pTT04iLCJhbGciOiJSUzI1NiJ9";
    public static final String signature = "BVOEpYE0VjvOd19ySFoQm2HBI4rPtvB73b9UDG5wmQ9iEdiQSj63zHjXpHJMFVXLTEnp87AZYBXcB61FfnVNKJpRDazmaJwomUBbFi59fC_BIrshryw2UMpDA7X1Ll7jUQ2_YkYK1_5T3dj0KFVz4_-GeFB1aS6gQUY0jaM9Y4pV1LZWb9mMD_i6Crk6qg8_iVtrXDMNavT8ntIUnNTg0gl4Fts0GnAcsSgwdABJ90QvywRnz9Imz3uqMSQ4zJ1OgxR_wiZQRZvAIlzFpw3-yXm3uwOyW4ZZLI3uicr3h043d46vkvVYvo0izUi_R3Eot6cZg1Fjv4hRiLZTg5KwAw";

    @Test
    void sign() throws CryptoException, NoSuchAlgorithmException {
        PrivateKey privateKey = getPrivateKey();
        FlattenedSignature sign = jws.sign(payload, privateKey);
        assertNotNull(sign);
        assertEquals(payloadSigned, sign.getPayload());
        assertEquals(protectedData, sign.getProtectedData());
        assertEquals(signature, sign.getSignature());
    }

    @Test
    void deSign() throws CryptoException, JsonProcessingException, ParseException {
        PublicKey publicKey = getPublicKey();
        FlattenedSignature flattenedSignature = FlattenedSignature.builder()
                .payload(payloadSigned)
                .protectedData(protectedData)
                .signature(signature)
                .build();
        String deSigned = jws.deSign(flattenedSignature.toJson(), publicKey);
        assertEquals(payload, deSigned);
    }
}