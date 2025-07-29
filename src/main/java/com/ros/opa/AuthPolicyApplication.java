package com.ros.opa;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class AuthPolicyApplication implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(AuthPolicyApplication.class, args);
    }

    @Override
    public void run(String... args) {
        RestTemplate restTemplate = new RestTemplate();

        String postUrl = "http://localhost:8080/api/policy/resource-access";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-User-Claim", getClaim());

    	Map<String, Object> body = new HashMap<>(); // or Map.of() for immutable
    	HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);		

        try {
            String response = restTemplate.postForObject(postUrl, request, String.class);
            System.out.println("Response: " + response);
        } catch (Exception e) {
            System.err.println("POST call failed: " + e.getMessage());
        }
    }

    private String getClaim() {
   		return "{\"sub\":\"user123\",\"role\":\"RoleA\",\"org\":\"Sales\"}";
    }
}

