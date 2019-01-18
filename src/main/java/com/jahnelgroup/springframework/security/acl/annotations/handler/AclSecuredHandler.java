package com.jahnelgroup.springframework.security.acl.annotations.handler;

import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.MutableAclService;

/**
 * Acl secured handler to create, update and delete ACLs.
 *
 * @author Steven Zgaljic
 */
public interface AclSecuredHandler {

    /**
     * Creates a new ACL for the saved Object.
     *
     * @param saved
     */
    void createAcl(Object saved);

    /**
     * Updates an existing ACL for the saved Object.
     *
     * @param saved
     */
    void updateAcl(Object saved);

    /**
     * Deletes the entire ACL for the provided Object.
     *
     * @param deleted
     */
    void deleteAcl(Object deleted);

    /**
     * Sets the {@link AclService} to use during ACL evaluation.
     *
     * @param aclService
     */
    void setAclService(MutableAclService aclService);

    /**
     * Sets the {@link PermissionFactory} to use during ACL evaluation.
     *
     * @param permissionFactory
     */
    void setPermissionFactory(PermissionFactory permissionFactory);

}
