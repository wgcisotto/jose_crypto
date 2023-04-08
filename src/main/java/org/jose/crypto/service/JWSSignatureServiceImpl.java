package org.jose.crypto.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import org.jose.crypto.exception.CryptoException;
import org.jose.crypto.exception.JsonUtilException;
import org.jose.crypto.model.FlattenedSignature;
import org.jose.crypto.utils.SignUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class JWSSignatureServiceImpl implements  JWSSignatureService {

    @Override
    public FlattenedSignature sign(String data, PrivateKey privateKey) throws CryptoException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] fingerprint = digest.digest(privateKey.getEncoded());
        Base64URL x5tString = Base64URL.encode(fingerprint);
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JOSE_JSON)
                .x509CertSHA256Thumbprint(x5tString)
                .build();
        JWSObject jwsObject= new JWSObject(jwsHeader, new Payload(data));
        try {
            jwsObject.sign(new RSASSASigner(privateKey));
        } catch (JOSEException e) {
            throw new CryptoException(String.format("Failed to sign data: {%s} using private key provided. ", data), e);
        }
        return FlattenedSignature.builder()
                .payload(jwsObject.getPayload().toBase64URL().toString())
                .protectedData(jwsObject.getHeader().toBase64URL().toString())
                .signature(jwsObject.getSignature().toString())
                .build();
    }

    @Override
    public String deSign(String signedData, PublicKey publicKey) throws CryptoException, ParseException {
        JWSObject jwsObject;
        try {
            jwsObject = JWSObject.parse(SignUtil.fromFlattenedToCompactSignature(signedData));
        } catch (JsonUtilException e) {
            throw new CryptoException(String.format("Failed to parse JWS string: {%s} to jwsObject. ", signedData), e);
        }
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        try {
            jwsObject.verify(verifier);
        } catch (JOSEException e) {
            throw new CryptoException(String.format("Failed to verify signature data: {%s} using public key provided.", signedData), e);
        }
        return jwsObject.getPayload().toString();
    }
}
