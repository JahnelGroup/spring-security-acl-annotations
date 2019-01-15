package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;

import java.io.Serializable;
import java.lang.reflect.Field;

public interface AclObjectIdLookupStrategy {

    Triple<Object, Field, Serializable> lookup(Object object) throws IllegalAccessException;

}
