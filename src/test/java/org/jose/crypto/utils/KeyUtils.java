package org.jose.crypto.utils;

import org.jose.crypto.exception.CryptoException;

import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyUtils {

    //TODO: read this info from a env file, to not commit it on github, do it before pushing it
    private static final String PUBLIC_KEY_BASE64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA28d3fG6vOQAoGhchKwKj" +
                    "g4m6Uw+hZiNhI/HSSH451SVqFHLfGJqx3IT2tD3sOuXdDANQwnLWu0es7tE9M1S+" +
                    "vm405pEkAuP9NiQWBuToM8uJvex4on0Y3+/MZZh+4mhZyKBWkPesizliHqFBMpJF" +
                    "uCoPDQb289cm1QkFyJAyCtkN+wygoxRNZEY3CjBwOmvtjNf8vPs7dzkTNWUauAHc" +
                    "uFvje7EbFKsJ6K75b/fn64MBJjHgQvRJiROl+qD6P/vHdr/WJySile971z5n1WMM" +
                    "9FR2HLcu1vO++rwx3y/1tAkv0/0seDXMvKPwjt5RoOGIugTomgPRSTiRRAcIM7Uw" +
                    "uQIDAQAB";

    //TODO: read this info from a env file, to not commit it on github, do it before pushing it
    private static final String PRIVATE_KEY_BASE64 =
            "MIIEpAIBAAKCAQEA28d3fG6vOQAoGhchKwKjg4m6Uw+hZiNhI/HSSH451SVqFHLf" +
                    "GJqx3IT2tD3sOuXdDANQwnLWu0es7tE9M1S+vm405pEkAuP9NiQWBuToM8uJvex4" +
                    "on0Y3+/MZZh+4mhZyKBWkPesizliHqFBMpJFuCoPDQb289cm1QkFyJAyCtkN+wyg" +
                    "oxRNZEY3CjBwOmvtjNf8vPs7dzkTNWUauAHcuFvje7EbFKsJ6K75b/fn64MBJjHg" +
                    "QvRJiROl+qD6P/vHdr/WJySile971z5n1WMM9FR2HLcu1vO++rwx3y/1tAkv0/0s" +
                    "eDXMvKPwjt5RoOGIugTomgPRSTiRRAcIM7UwuQIDAQABAoIBAFweHdHU3rKogyZ0" +
                    "XV2WrIx8lNEtsvuJhrS3LelepsTU+sJ5Z1L7u+LvBCyF69a/88eOODJYSfKTV0N+" +
                    "BgXW1mAg9yFQ4mQnxUEFHQpktYLIJAKr8+A/SMbLzsMiiMRC8qbptX7roLF2Ks8l" +
                    "zZrxvjEzx70xFx8bJdaTAo6PCbqLeo5pAp9gUl9hIxvzYcvx2mz75z0olchcd7xI" +
                    "+f9dP40TsmK20hZ49aECmILB48Q6cjXD7aZlfF+Yy9umzbiAKVPN6J7fwY8PEufZ" +
                    "HKXvMmxP2P5lsimhiWh+rN+yhoWrZ2/znTTTqg8NNiJgZmtXC7f37oCfcWS6q60r" +
                    "frXDr9UCgYEA97fEc99xioj06oMaeuJ+p/2tS4injuHNeQmDFKmrtX5Nhbxxo7T4" +
                    "UAq1j6NOk8QSbkzeeCjePIzQrNbOFtGmzvBlo9GhgV5TTJEtGXfxPfeCVDL+S4+K" +
                    "+OQ8CUnSFYmgmfduXmCRbfr4XH+H9kuzlVY/M08WC5C1SmDDNdI7XvMCgYEA4yCS" +
                    "CqtlYneHJJxsTonMnMYHNd5H2R9d3T8yH3oIEKuakN7bqiKK4kItLcTF+OegYQsE" +
                    "QF6TGAmkmd7vvQgKhwf1L9ahuNIh5w6PVvdxae4yI94o1F+1ULUQPtEJTr2oqnuF" +
                    "jvw5mxzlsZHQ5uyQDFtXYN7gvk9gubKFl2BAVKMCgYEAtbncptzO4MCkW74eGPQ7" +
                    "0mWpUfZIZeuE3zx5Kxll3Flx6aBbBavnVmDk3SECrihzFPPTaPciQe1T0NgsjFT1" +
                    "OG7nQYyyHMPj/BGssjhpg/olZDucjjYZz4kv+ehr9Fzossrv7tCNH8+zj7gHOEpE" +
                    "zlNdPfjQxV89f/kIfF1kLL0CgYBdBWTqu8G9L0kJJItzKxrDBpPDazMv6JnP2GcV" +
                    "3yvYb//Q34VFy/nnqsTIHvQZ+fuEYzetiU5jJOfmIRk86UMuhILVwejgQieicyMf" +
                    "sh4gDW85o25DdKNU16M8pu5R8nlWwVo08nZBYfds31SYj0B73xkNUprnNqldxJDU" +
                    "K5aNUwKBgQDcTgryUiMToYEuBOAKtC3KYJ0r3bqThz9HEH4yEopRfI4HAqGhjghO" +
                    "pEycW6XW1zlgggx5WzqMKtgs7mFDMPWwGST8vQCjuD3C6cUmNzo4yGhYf8K79UqR" +
                    "pH7mzYFMKSuCsWNzkczhAAjWNuaMLdrNZaZbtQV/xnHDV64wyNTKKg==";



    public static PublicKey getPublicKey() throws CryptoException {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        return keyPairGenerator.getPublicKeyFromBase64String(PUBLIC_KEY_BASE64);
    }

    public static PrivateKey getPrivateKey() throws CryptoException {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        PrivateKey privateKeyFromBase64String = keyPairGenerator.getPrivateKeyFromBase64String(PRIVATE_KEY_BASE64);
        return privateKeyFromBase64String;
    }
}
