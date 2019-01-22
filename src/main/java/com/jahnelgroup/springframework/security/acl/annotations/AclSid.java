package com.jahnelgroup.springframework.security.acl.annotations;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface AclSid {
    @AliasFor("principal")
    boolean  value() default true;

    @AliasFor("value")
    boolean principal() default true;

    String expression() default "";
}