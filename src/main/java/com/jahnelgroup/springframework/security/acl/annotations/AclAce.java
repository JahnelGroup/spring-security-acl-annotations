package com.jahnelgroup.springframework.security.acl.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
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
    String[] permissions() default {};
    boolean granting() default true;
    AclSid sid() default @AclSid();
}

