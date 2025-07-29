package com.ros.opa.auth_policy;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.styra.opa.wasm.OpaPolicy;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.*;

@SpringBootTest
class AuthPolicyApplicationTests {

    @Test
    public void testClassValidation2() throws Exception {
        // Initialize the WasmLoader with the bundle path in your classpath
        WasmLoader loader = new WasmLoader("policy/bundle.tar.gz");

        // Load the policy.wasm file from the bundle
        byte[] wasmBytes = loader.getPolicy("policy.wasm");

        // Initialize OPA policy with raw wasm bytes
        OpaPolicy policy = OpaPolicy.builder()
                .withPolicy(new ByteArrayInputStream(wasmBytes))
                .build();

        String inputJson = """
        {
        "claims": {
            "validationSet": {
            "validationList": ["9991283", "9991284", "9991285"]
            }
        },
        "output": {
            "classes": ["9991283", "9991284", "9492", "33295837"]
        },
        
        "roles": ["role.admin6","order.read","supplier.read"],

        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "department": "IT"
        },        
        "validateField": "classes"
        }
        """;

        String resultJson = policy.evaluate(inputJson);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(resultJson);

        // OPA evaluation result is an array with one object containing "result"
        JsonNode firstResult = rootNode.get(0).get("result");

        boolean allow = firstResult.get("allow").asBoolean();
        JsonNode invalidClassesNode = firstResult.get("invalidClasses");

        System.out.println("allow? " + allow + " invalidClasses " + invalidClassesNode);

        assertTrue(invalidClassesNode.isArray(), "invalidClasses should be an array");
    } 

  }
