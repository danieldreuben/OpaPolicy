package com.ros.opa;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.ros.opa.auth_policy.CheckPolicy;

import java.util.Map;

@RestController
@RequestMapping("/api/policy")
public class PolicyController {

    @PostMapping("/resource-access")
    @CheckPolicy("scim.authz/allow")
    public ResponseEntity<String> getAllItems(@RequestBody Map<String, Object> input) {
        System.out.println("getAllItems()..");
        return ResponseEntity.ok("Response.. '");
    }
}
