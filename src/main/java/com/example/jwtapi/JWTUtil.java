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

    public static RSAKey getJWKFromProperties(String env) throws IOException, ParseException {
        String jwkJson = null;

        try (InputStream inputStream =
                     JWTUtil.class.getClassLoader().getResourceAsStream(KEY_FILE_NAME);
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            if (inputStream == null) {
                throw new IOException("Could not find " + KEY_FILE_NAME + " in the classpath.");
            }
            String line;
            while ((line = reader.readLine()) != null) {
                // Check if the line matches the pattern {domain}|{env}|jwk-s-s|{JWK}
                String[] parts = line.split("\\|", 4);
                if (parts.length == 4 && parts[1].equalsIgnoreCase(env) && "jwk-s-s".equalsIgnoreCase(parts[2])) {
                    jwkJson = parts[3].trim();
                    break;
                }
            }
        }

        if (jwkJson == null) {
            throw new IllegalArgumentException("JWK JSON not found in properties file for environment: " + env);
        }

        JWK jwk = JWK.parse(jwkJson);
        if (!(jwk instanceof RSAKey)) {
            throw new IllegalArgumentException("JWK is not an RSA key");
        }
        return (RSAKey) jwk;
    }
}
