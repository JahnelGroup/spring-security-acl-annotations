package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclAce;
import com.jahnelgroup.springframework.security.acl.annotations.AclObjectId;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;

import java.lang.reflect.Field;
import java.util.List;

public interface AclAceLookupStrategy {

    Tuple<Object, List<Tuple<Field, AclAce>>> lookup(Object object) throws IllegalAccessException;

}
