package com.ros.opa.policy;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;
import java.lang.annotation.RetentionPolicy;


@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface CheckPolicy {
    String value(); // the OPA entrypoint (e.g. "scim.authz.roles/allow")
}
