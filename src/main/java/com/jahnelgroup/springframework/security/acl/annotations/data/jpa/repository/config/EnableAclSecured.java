package com.jahnelgroup.springframework.security.acl.annotations.data.jpa.repository.config;

import com.jahnelgroup.springframework.security.acl.annotations.config.JpaAclSecuredRegistrar;
import org.springframework.context.annotation.Import;
import com.jahnelgroup.springframework.security.acl.annotations.handler.AclSecuredHandler;
import com.jahnelgroup.springframework.security.acl.annotations.handler.DefaultAclSecuredHandler;

import org.springframework.security.acls.model.AclService;

import java.lang.annotation.*;

/**
 * Enable Spring ACL first process with JPA entity managed beans.
 *
 * Derived and inspired by {@link org.springframework.data.jpa.repository.config.EnableJpaAuditing}
 */
@Inherited
@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(JpaAclSecuredRegistrar.class)
public @interface EnableAclSecured {

    /**
     * Configures the {@link AclSecuredHandler} bean to be used, otherwise defaults to a singleton instance of
     * {@link DefaultAclSecuredHandler}.
     *
     * @return
     */
    String aclSecuredHandlerRef() default "";

    /**
     * Configures the {@link AclService} bean to be used, otherwise defaults to lookup a bean named aclService.
     *
     * @return
     */
    String aclServiceRef() default "aclService";
}
