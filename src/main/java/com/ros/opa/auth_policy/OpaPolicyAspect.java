package com.ros.opa.auth_policy;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.styra.opa.wasm.OpaPolicy;

import jakarta.servlet.http.HttpServletRequest;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

@Aspect
@Component
public class OpaPolicyAspect {
    
    private OpaPolicy policy; 
    private final ObjectMapper objectMapper = new ObjectMapper();

    public OpaPolicyAspect() {
        try {
            // Initialize the WasmLoader with the bundle path in your classpath
            WasmLoader loader = new WasmLoader("policy/bundle.tar.gz");

            // Load the policy.wasm file from the bundle
            byte[] wasmBytes = loader.getPolicy("policy.wasm");

            // Initialize OPA policy with raw wasm bytes
            this.policy = OpaPolicy.builder()
                    .withPolicy(new ByteArrayInputStream(wasmBytes))
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Around("@annotation(checkPolicy)")
    public Object enforcePolicy(ProceedingJoinPoint pjp, CheckPolicy checkPolicy) throws Throwable {
        ObjectNode inputNode = objectMapper.createObjectNode();

        // Get method name
        Method method = ((MethodSignature) pjp.getSignature()).getMethod();
        String methodName = method.getName();
        inputNode.put("method", methodName);

        // Get JSON claims from header
        HttpServletRequest request = getCurrentHttpRequest();
        if (request != null) {
            String claimsJson = request.getHeader("X-User-Claims");

            if (claimsJson != null && !claimsJson.isEmpty()) {
                try {
                    JsonNode claimsNode = objectMapper.readTree(claimsJson);
                    if (claimsNode.isObject()) {
                        inputNode.setAll((ObjectNode) claimsNode);  // Merge claims into input
                    } else {
                        throw new IllegalArgumentException("X-User-Claims must be a JSON object");
                    }
                } catch (Exception e) {
                    throw new IllegalArgumentException("Invalid JSON in X-User-Claims header", e);
                }
            }
        }

        // Evaluate policy with JsonNode
        //boolean allowed = policy.evaluate(inputNode);  // Your policy service
        String resultJson = policy.evaluate(inputNode);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(resultJson);
        // OPA evaluation result is an array with one object containing "result"
        JsonNode firstResult = rootNode.get(0).get("result");
        System.out.println("AOP Policy Response: " + firstResult);
        
        boolean allowed = firstResult.path("allow").asBoolean();
        if (!allowed) {
            throw new SecurityException("Access denied by OPA policy" + allowed);
        }

        // Proceed with the original method
        Object result = pjp.proceed();

        return result;
    }


    private HttpServletRequest getCurrentHttpRequest() {
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            if (requestAttributes instanceof ServletRequestAttributes) {
                return ((ServletRequestAttributes) requestAttributes).getRequest();
            }
            return null;
        }
/* 
    private Map<String, Object> extractInput(ProceedingJoinPoint pjp) {
        MethodSignature signature = (MethodSignature) pjp.getSignature();
        String[] paramNames = signature.getParameterNames();
        Object[] args = pjp.getArgs();

        Map<String, Object> input = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            input.put(paramNames[i], args[i]);
        }
        return input;
    } */
}

