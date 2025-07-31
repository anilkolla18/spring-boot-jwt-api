package com.example.jwtapi;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;

public class TokenService {

    public static String genToken(String pubSignKey, String privSignKey, String encryptKeyName, Properties envProps) throws Exception {
        String encryptKey = envProps.getProperty(encryptKeyName);

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", envProps.getProperty("apic.issuer"));
        claims.put("sub", "CLIENT_ID");
        claims.put("aud", "OPERATION_PATH");
        claims.put("lch-provider-org", "PROVIDER_ORG");
        claims.put("lch-catalog", "CATALOG");
        claims.put("lch-client-app", "APP");
        claims.put("lch-client-org", "CONSUMER_ORG");

        // Create signed JWT
        Payload payloadToSign = new Payload(claims);
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        JWSObject signedJWT = new JWSObject(jwsHeader, payloadToSign);

        // Use private key from JWTUtil
        RSAKey rsaKey = JWTUtil.getFullSignJWK();
        signedJWT.sign(new RSASSASigner(rsaKey.toRSAPrivateKey()));

        // Create encrypted JWT with a supported algorithm
        // We'll use A128KW (AES Key Wrap) with A128CBC-HS256 for content encryption
        // A128KW requires a 16-byte key
        JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128CBC_HS256);
        Payload payloadToEncrypt = new Payload(signedJWT);
        JWEObject encryptedJWT = new JWEObject(jweHeader, payloadToEncrypt);

        // The key for A128KW must be 16 bytes (128 bits)
        // If your key is shorter, you'll need to pad it.
        byte[] keyBytes = encryptKey.getBytes("UTF-8");
        if (keyBytes.length != 16) {
            throw new IllegalArgumentException("Encryption key must be exactly 16 bytes long for A128KW");
        }
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        // Use AESEncrypter with the correct key
        AESEncrypter encrypter = new AESEncrypter(secretKey);
        encryptedJWT.encrypt(encrypter);

        return encryptedJWT.serialize();
    }
}