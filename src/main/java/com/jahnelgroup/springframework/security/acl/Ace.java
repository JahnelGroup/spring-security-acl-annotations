package com.jahnelgroup.springframework.security.acl;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.FIELD})
public @interface Ace {
    boolean principal() default true;
    boolean granting() default true;
    String[] permissions() default {};
}