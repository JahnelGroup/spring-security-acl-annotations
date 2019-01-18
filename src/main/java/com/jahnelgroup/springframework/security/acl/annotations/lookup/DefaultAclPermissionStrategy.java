package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.model.Permission;

/**
 * Default implementation of {@link AclPermissionLookStrategy}
 */
public class DefaultAclPermissionStrategy implements AclPermissionLookStrategy{

    private PermissionFactory permissionFactory;

    public DefaultAclPermissionStrategy(PermissionFactory permissionFactory){
        this.permissionFactory = permissionFactory;
    }

    @Override
    public Permission lookup(String name) {
        return permissionFactory.buildFromName(name.toUpperCase());
    }
}
