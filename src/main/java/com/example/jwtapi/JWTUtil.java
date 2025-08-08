package com.example.jwtapi;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.ParseException;

public class JWTUtil {

    private static final String KEY_FILE_NAME = "keys.properties";
    private static final String JWK_PROPERTY_PREFIX = "apimanager-nonprod.labcorp.com|DEVINT|jwk-s-s|";

    public static RSAKey getFullSignJWK() throws IOException, ParseException {
        String jwkJson = loadJWKFromProperties();
        JWK jwk = JWK.parse(jwkJson);
        if (!(jwk instanceof RSAKey)) {
            throw new IllegalArgumentException("JWK is not an RSA key");
        }
        return (RSAKey) jwk;
    }

    private static String loadJWKFromProperties() throws IOException {
        try (InputStream inputStream =
                     JWTUtil.class.getClassLoader().getResourceAsStream(KEY_FILE_NAME);
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            if (inputStream == null) {
                throw new IOException("Could not find " + KEY_FILE_NAME + " in the classpath.");
            }
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(JWK_PROPERTY_PREFIX)) {
                    String jwkJson = line.substring(JWK_PROPERTY_PREFIX.length()).trim();
                    System.out.println("Extracted JWK JSON: " + jwkJson);
                    return jwkJson;
                }
            }
        }
        throw new IllegalArgumentException("JWK JSON not found in properties file with the expected prefix.");
    }
}
