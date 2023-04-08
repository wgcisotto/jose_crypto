package org.jose.crypto.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.Base64URL;
import org.jose.crypto.exception.CryptoException;
import org.jose.crypto.model.FlattenedEncrypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class JWEAsymmetricCryptoServiceImpl implements JWEAsymmetricCryptoService {

    @Override
    public FlattenedEncrypt encrypt(String data, PublicKey publicKey) throws CryptoException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] fingerprint = digest.digest(publicKey.getEncoded());
        Base64URL x5tString = Base64URL.encode(fingerprint);
        JWEHeader jweHeader = new JWEHeader
                .Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                .type(JOSEObjectType.JOSE_JSON)
                .x509CertSHA256Thumbprint(x5tString)
                .build();
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(data));
        try {
            jweObject.encrypt(new RSAEncrypter((RSAPublicKey) publicKey));
        } catch (JOSEException e) {
            throw new CryptoException(String.format("Failed to encrypt data: {%s} using public key provided. ", data), e);
        }
        return FlattenedEncrypt.builder()
                .protectedData(jweObject.getHeader().toBase64URL().toString())
                .encryptedKey(jweObject.getEncryptedKey().toString())
                .iv(jweObject.getIV().toString())
                .ciphertext(jweObject.getCipherText().toString())
                .tag(jweObject.getAuthTag().toString())
                .build();
    }

    @Override
    public String decrypt(FlattenedEncrypt dataEncrypted, PrivateKey privateKey) throws CryptoException {
        JWEObject jweObject;
        String JWECompact = dataEncrypted.toCompactEncrypt();
        try {
            jweObject = JWEObject.parse(JWECompact);
        } catch (ParseException e) {
            throw new CryptoException(String.format("Failed to parse JWE Object: {%s}.", JWECompact), e);
        }
        RSADecrypter decrypter = new RSADecrypter(privateKey);
        try {
            jweObject.decrypt(decrypter);
        } catch (JOSEException e) {
            throw new CryptoException(String.format("Failed to decrypt JWE Object: {%s} using private key provided.", JWECompact), e);
        }
        return jweObject.getPayload().toString();
    }
}
