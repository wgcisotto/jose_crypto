package org.jose.crypto.service;

import org.jose.crypto.exception.CryptoException;
import org.jose.crypto.model.FlattenedEncrypt;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface JWEAsymmetricCryptoService {

    FlattenedEncrypt encrypt(String data, PublicKey publicKey) throws CryptoException, NoSuchAlgorithmException;

    String decrypt(FlattenedEncrypt dataEncrypted, PrivateKey privateKey) throws CryptoException;

}
