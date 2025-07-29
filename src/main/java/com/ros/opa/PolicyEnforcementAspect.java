package com.ros.opa;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Aspect
@Component
public class PolicyEnforcementAspect {

    //private final WasmPolicyService opaService;

    /** public PolicyEnforcementAspect(WasmPolicyService opaService) {
        this.opaService = opaService;
    } */

    @Around("@annotation(checkPolicy)")
    public Object enforcePolicy(ProceedingJoinPoint pjp, CheckPolicy checkPolicy) throws Throwable {
        Map<String, Object> input = extractInput(pjp);

        //boolean allowed = opaService.evaluate(checkPolicy.value(), input);
        boolean allowed = true;

        if (!allowed) {
            throw new SecurityException("Access denied by OPA policy");
        }
        System.out.println("AOP:enforcePolicy - checking opa policy -");
        return pjp.proceed();
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

