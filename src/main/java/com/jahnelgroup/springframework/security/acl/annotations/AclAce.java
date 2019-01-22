package com.jahnelgroup.springframework.security.acl.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.domain.PermissionFactory;

/**
 * Represents the configuration of an Access Control Entry (ACE) for an Access Control List (ACL).
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface AclAce {

    /**
     * String array of {@link Permission} names to be applied to the associated {@link Sid}'s for this mapping. The
     * registered {@link PermissionFactory} will be used to lookup the {@link Permission}
     *
     * @return
     */
    @AliasFor("value")
    String[] permissions() default {};

    /**
     * String array of {@link Permission} names to be applied to the associated {@link Sid}'s for this mapping. The
     * registered {@link PermissionFactory} will be used to lookup the {@link Permission}
     *
     * @return
     */
    @AliasFor("permissions")
    String[] value() default {};

    /**
     * Are these permissions granting or denying?
     *
     * @return
     */
    boolean granting() default true;

    /**
     * In the scenario that {@link AclAce} is defined on String, Character or Number this attribute allows
     * you indicate if the values are principal or granted authority.
     * @return
     */
    AclSid[] sid() default {};
}

