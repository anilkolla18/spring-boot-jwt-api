package com.example.jwtapi;

import org.springframework.web.bind.annotation.*;
import java.util.Properties;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/token")
public class TokenController {

    @GetMapping("/generate")
    public Map<String, String> generateToken() throws Exception {
        Properties envProps = new Properties();
        envProps.setProperty("encryptKey", "MySecretKey12345");
        envProps.setProperty("apic.issuer", "issuer-value");

        String jwtToken = TokenService.genToken(null, null, "encryptKey", envProps);

        Map<String, String> response = new HashMap<>();
        response.put("jwtToken", jwtToken);

        return response;
    }
}