package com.ros.opa;

import java.util.HashMap;
import java.util.List;
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

	public Map<String, Object> getTestClaimMap() {
		Map<String, Object> data = new HashMap<>();

		// Roles
		data.put("roles", List.of("auditor", "order.read", "supplier.read", "admin.role"));

		// Claims
		Map<String, Object> validationSet = Map.of(
			"validationList", List.of("9991283", "9991284", "9991285")
		);
		data.put("claims", Map.of("validationSet", validationSet));

		// SCIM User extension
		data.put("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
				Map.of("department", "IT"));

		return data;
	}


    private String getClaim() {
    return "{"
         + "\"roles\": [\"auditor\", \"order.read\", \"supplier.read\", \"admin.role\"],"
         + "\"claims\": {"
         + "  \"validationSet\": {"
         + "    \"validationList\": [\"9991283\", \"9991284\", \"9991285\"]"
         + "  }"
         + "},"
         + "\"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\": {"
         + "  \"department\": \"IT\""
         + "}"
         + "}";
    }
}

