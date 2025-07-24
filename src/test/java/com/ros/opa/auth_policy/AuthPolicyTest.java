package com.ros.opa.auth_policy;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.*;
import org.apache.commons.compress.archivers.tar.*;

import java.util.zip.GZIPInputStream;
import com.styra.opa.wasm.OpaPolicy;

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

@SpringBootTest
class AuthPolicyApplicationTests {
        
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
                "classes": ["9991283", "9991284","111111"]
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
System.out.println("allow? " + allow);            
            JsonNode invalidClassesNode = firstResult.get("invalidClasses");
System.out.println("invalidClasses" + invalidClassesNode);
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
    }
}
