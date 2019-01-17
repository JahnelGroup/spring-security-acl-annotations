package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclSid;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import java.io.Serializable;
import java.lang.reflect.Field;

public interface AclSidLookupStrategy {

    Triple<Object, Field, AclSid> lookup(Object object) throws IllegalAccessException;

}
