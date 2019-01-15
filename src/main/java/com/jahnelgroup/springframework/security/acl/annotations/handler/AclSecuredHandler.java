package com.jahnelgroup.springframework.security.acl.annotations.handler;

public interface AclSecuredHandler {

    void saveAcl(Object saved);
    void deleteAcl(Object deleted);

}
