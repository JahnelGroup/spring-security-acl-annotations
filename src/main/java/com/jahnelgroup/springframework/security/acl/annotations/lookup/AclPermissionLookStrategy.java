package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import org.springframework.security.acls.model.Permission;

/**
 * Looks up a {@link Permission} based on it's String name.
 *
 * @author Steven Zgaljic
 */
public interface AclPermissionLookStrategy {

    /**
     * Returns the associated {@link Permission} based on it's name.
     *
     * @param name
     * @return
     */
    Permission lookup(String name);

}
