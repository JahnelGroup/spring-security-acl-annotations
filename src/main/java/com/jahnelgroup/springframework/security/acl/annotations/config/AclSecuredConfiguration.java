package com.jahnelgroup.springframework.security.acl.annotations.config;

import com.jahnelgroup.springframework.security.acl.annotations.handler.AclSecuredHandler;

/**
 * Configuration information for acl annotations.
 *
 * Derived and inspired by {@link org.springframework.data.auditing.config.AuditingConfiguration}
 *
 * @author Steven Zgaljic
 */
public interface AclSecuredConfiguration {

    /**
     * Returns the bean name of the {@link AclSecuredHandler} instance to be used.
     * @return
     */
    String getAclSecuredHandlerRef();

    /**
     * Returns the bean name of the {@link org.springframework.security.acls.model.AclService} instance to be used.
     * @return
     */
    String getAclServiceRef();

}
