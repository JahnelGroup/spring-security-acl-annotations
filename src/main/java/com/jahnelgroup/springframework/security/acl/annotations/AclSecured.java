package com.jahnelgroup.springframework.security.acl.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
public @interface AclSecured {
    boolean principal() default true;
    String[] permissions() default {};
}