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

//    private SidProvider sidProvider;
//    private PermissionFactory permissionFactory;
//
//    private List<Class<? extends DefaultAclSecuredHandler>> aspects = new ArrayList<>();
//
//    public AclSecuredConfiguration enableCrudRepositories(){
//        aspects.add(CrudRepositoryAclSecuredAspect.class);
//        return this;
//    }
//
//    public SidProvider getSidProvider() {
//        return sidProvider;
//    }
//
//    public AclSecuredConfiguration setSidProvider(SidProvider sidProvider) {
//        this.sidProvider = sidProvider;
//        return this;
//    }
//
//    public PermissionFactory getPermissionFactory() {
//        return permissionFactory;
//    }
//
//    public AclSecuredConfiguration setPermissionFactory(PermissionFactory permissionFactory) {
//        this.permissionFactory = permissionFactory;
//        return this;
//    }
//
//    public List<Class<? extends DefaultAclSecuredHandler>> getAspects() {
//        return aspects;
//    }
//
//    public AclSecuredConfiguration setAspects(List<Class<? extends DefaultAclSecuredHandler>> aspects) {
//        this.aspects = aspects;
//        return this;
//    }
}
