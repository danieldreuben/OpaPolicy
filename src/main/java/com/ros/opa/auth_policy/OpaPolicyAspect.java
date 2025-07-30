package com.ros.opa.auth_policy;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

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
        Method method = ((MethodSignature) pjp.getSignature()).getMethod();
        String methodName = method.getName();
        //boolean allowed = opaService.evaluate(checkPolicy.value(), input);
        boolean allowed = true;

        //Map<String, Object> input = extractInput(pjp);

        // Get current HTTP request
        HttpServletRequest request = getCurrentHttpRequest();
        if (request != null) {
            // Example: get a specific header, e.g. "X-User-Token"
            String headerValue = request.getHeader("X-User-Token");
            // Add header to input map for OPA evaluation
            input.put("claim", headerValue);
        }       
System.out.println("claim-header " + input.get("claim"));

        if (!allowed) {
            throw new SecurityException("Access denied by OPA policy");
        }
        System.out.println("AOP:enforcePolicy - checking opa policy -" + methodName);
        // Proceed with the original method and capture the result
        Object result = pjp.proceed();

        // Log or inspect the result
        System.out.println("AOP: enforcePolicy - method returned: " + result);

        // Optionally modify result before returning
        return result;
    }

    private HttpServletRequest getCurrentHttpRequest() {
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            if (requestAttributes instanceof ServletRequestAttributes) {
                return ((ServletRequestAttributes) requestAttributes).getRequest();
            }
            return null;
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

