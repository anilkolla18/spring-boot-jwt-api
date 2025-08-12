package com.example.jwtapi;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import java.util.*;
import java.util.UUID; // Added for JTI claim
import java.util.Date; // Added for expiration claim
import java.util.concurrent.TimeUnit; // Added for expiration claim

public class TokenService {

    static final String ENV = "DEVInt";

    public static String genToken(Properties envProps) throws Exception {

        Map<String, Object> claims = new HashMap<>();
        // Add the JWT ID (jti) claim with a new UUID
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iss", envProps.getProperty("apic.issuer"));
        claims.put("sub", "6554e38eeecb6aa01ee37d97709f8c2d");
        claims.put("aud", "/hello");

        // Add the Expiration (exp) claim based on a 3600-second validity period
        long validityPeriodSeconds = 3600; // 1 hour
        Date now = new Date();
        Date expirationTime = new Date(now.getTime() + TimeUnit.SECONDS.toMillis(validityPeriodSeconds));
        // JWT 'exp' claim is a NumericDate, representing seconds since Unix epoch
        claims.put("exp", expirationTime.getTime() / 1000L);

        Map<String, Object> claimsPrv = new HashMap<>();
        claimsPrv.put("lch-provider-org", "lcd");
        claimsPrv.put("lch-catalog", "devint");
        claimsPrv.put("lch-client-app", "devint-test-app");
        claimsPrv.put("lch-client-org", "devint-test-consumer-org");
        claims.put("private", claimsPrv);
        System.out.println("claims : " + claims);

        // Create signed JWT
        Payload payloadToSign = new Payload(claims);
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        JWSObject signedJWT = new JWSObject(jwsHeader, payloadToSign);

        // Use private key from JWTUtil for signing
        RSAKey rsaKey = (RSAKey) JWTUtil.getJWKFromProperties(ENV, "jwk-s-s");
        signedJWT.sign(new RSASSASigner(rsaKey.toRSAPrivateKey()));

        // Create encrypted JWT with DIR algorithm
        JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
        Payload payloadToEncrypt = new Payload(signedJWT);
        JWEObject encryptedJWT = new JWEObject(jweHeader, payloadToEncrypt);

        // Use key from JWTUtil for encryption
        OctetSequenceKey jwk = (OctetSequenceKey) JWTUtil.getJWKFromProperties(ENV, "jwk-s-e");
        byte[] jwkBytes = jwk.toByteArray();

        // Encrypt using DirectEncrypter with the raw key bytes
        DirectEncrypter encrypter = new DirectEncrypter(jwkBytes);
        encryptedJWT.encrypt(encrypter);

        return encryptedJWT.serialize();
    }
}
