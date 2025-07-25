package com.ros.opa.auth_policy;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ros.opa.WasmLoader;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.*;
import com.styra.opa.wasm.OpaPolicy;

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
        
        "roles": ["role.admin","order.read","supplier.read"],

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
        
    //@Test
    public void testClassValidation3() throws Exception {
        // Initialize the WasmLoader with the bundle path in your classpath
        WasmLoader loader = new WasmLoader("policy/bundle.tar.gz");

        // Load the new policy2.wasm file from the bundle
        byte[] wasmBytes = loader.getPolicy("policy2.wasm");

        // Initialize OPA policy with raw wasm bytes
        OpaPolicy policy = OpaPolicy.builder()
                .withPolicy(new ByteArrayInputStream(wasmBytes))
                .build();

        // Input JSON matching your new policy2 expectations (roles and department)
        String inputJson = """
        {
          "roles": ["reader"],
          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "department": "IT"
          }
        }
        """;

        String resultJson = policy.evaluate(inputJson);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(resultJson);

        // OPA evaluation result is an array with one object containing "result"
        JsonNode firstResult = rootNode.get(0).get("result");

        boolean allow = firstResult.asBoolean();

        System.out.println("allow? " + allow);

        assertTrue(allow, "Expected allow to be true for reader in IT");
    }

    /*@Test
    public void wasmLoader() {
        System.out.println("[wasmLoader]");
        WasmLoader wasm = new WasmLoader("policy/bundle.tar.gz");
        System.out.println(wasm);
    }

    @Test
    public void testClassValidation() throws Exception {
        try (InputStream bundleStream = getClass().getClassLoader().getResourceAsStream("policy/bundle.tar.gz")) {
            //assertNotNull(bundleStream, "Policy bundle not found in resources");

            // Extract raw wasm bytes from tar.gz bundle
            byte[] wasmBytes = extractWasmFromTarGz(bundleStream);

            // Initialize OPA policy with raw wasm bytes using .withPolicy()
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
                "classes": ["9991283", "9991284"]
              },
              "validateField": "classes"
            }
            """;

            String resultJson = policy.evaluate(inputJson);

            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(resultJson);

            // OPA evaluation result is an array with one object containing "result"
            JsonNode firstResult = rootNode.get(0).get("result");
            //assertNotNull(firstResult, "Expected 'result' field in OPA evaluation response");

            boolean allow = firstResult.get("allow").asBoolean();
          
            JsonNode invalidClassesNode = firstResult.get("invalidClasses");
System.out.println("allow? " + allow + " invalidClasses " + invalidClassesNode);
            //assertFalse(allow, "Expected allow to be false");
            assertTrue(invalidClassesNode.isArray(), "invalidClasses should be an array");
            //assertEquals(1, invalidClassesNode.size(), "Expected exactly one invalid class");
            //assertEquals("9991286", invalidClassesNode.get(0).asText());
        }
    }

    private byte[] extractWasmFromTarGz(InputStream bundleStream) throws IOException {
        try (GZIPInputStream gis = new GZIPInputStream(bundleStream);
            TarArchiveInputStream tis = new TarArchiveInputStream(gis)) {

            TarArchiveEntry entry;
            while ((entry = tis.getNextTarEntry()) != null) {
                if (entry.getName().endsWith("policy.wasm")) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = tis.read(buffer)) != -1) {
                        baos.write(buffer, 0, bytesRead);
                    }
                    return baos.toByteArray();
                }
            }
        }
        throw new FileNotFoundException("policy.wasm not found in bundle");
    } */
}
