package org.jose.crypto.service;

import org.jose.crypto.exception.CryptoException;
import org.jose.crypto.model.FlattenedSignature;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;

public interface JWSSignatureService {

    FlattenedSignature sign(String data, PrivateKey privateKey) throws CryptoException, NoSuchAlgorithmException;

    String deSign(String signedData, PublicKey publicKey) throws CryptoException, ParseException;

}