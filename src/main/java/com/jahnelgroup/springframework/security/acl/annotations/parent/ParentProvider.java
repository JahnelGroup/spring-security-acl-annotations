package com.jahnelgroup.springframework.security.acl.annotations.parent;

import com.jahnelgroup.springframework.security.acl.annotations.handler.Tuple;

import java.io.Serializable;

public interface ParentProvider {

    Tuple<Class, Serializable> getParentObjectIdentity(Object target) throws IllegalAccessException;

}
