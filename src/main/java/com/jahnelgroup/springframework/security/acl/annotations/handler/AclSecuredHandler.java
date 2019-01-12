package com.jahnelgroup.springframework.security.acl.annotations.handler;

public interface AclSecuredHandler {

    void saveAcl(Object saved);
    void saveAcl(Iterable<?> saved);

    void deleteAcl(Object deleted);
    void deleteAcl(Iterable<?> deleted);

    //void deleteAclByObjectId(Class clazz, Serializable id) throws Exception;

}
