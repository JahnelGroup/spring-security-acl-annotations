package com.jahnelgroup.springframework.security.acl.annotations.mapper;

import com.jahnelgroup.springframework.security.acl.annotations.Ace;
import org.springframework.security.acls.model.Sid;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.List;

public interface AclEntryToSidsMapper {

    List<Sid> mapFieldToSids(Object object, Field field, Ace aclEntry) throws IllegalAccessException;

}
