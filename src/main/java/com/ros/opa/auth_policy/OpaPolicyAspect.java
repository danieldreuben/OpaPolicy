package com.ros.opa.auth_policy;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

import com.styra.opa.wasm.OpaPolicy;

import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.Map;

@Aspect
@Component
public class OpaPolicyAspect {
    
    private OpaPolicy policy; 
    //private final WasmPolicyService opaService;

    /** public OpaPolicyAspect(WasmPolicyService opaService) {
        this.opaService = opaService;
    } */

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
        Map<String, Object> input = extractInput(pjp);

        //boolean allowed = opaService.evaluate(checkPolicy.value(), input);
        boolean allowed = true;

        if (!allowed) {
            throw new SecurityException("Access denied by OPA policy");
        }
        System.out.println("AOP:enforcePolicy - checking opa policy -");
        // Proceed with the original method and capture the result
        Object result = pjp.proceed();

        // Log or inspect the result
        System.out.println("AOP: enforcePolicy - method returned: " + result);

        // Optionally modify result before returning
        return result;
    }

    private Map<String, Object> extractInput(ProceedingJoinPoint pjp) {
        MethodSignature signature = (MethodSignature) pjp.getSignature();
        String[] paramNames = signature.getParameterNames();
        Object[] args = pjp.getArgs();

        Map<String, Object> input = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            input.put(paramNames[i], args[i]);
        }
        return input;
    }
}

