package com.jahnelgroup.springframework.security.acl.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface AclAce {
    String[] permissions() default {};
    boolean granting() default true;
    AclSid sid() default @AclSid();
}
