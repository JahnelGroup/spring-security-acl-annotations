package com.jahnelgroup.springframework.security.acl.annotations.mapper;

import com.jahnelgroup.springframework.security.acl.annotations.AclAce;
import org.springframework.security.acls.model.Sid;

import java.lang.reflect.Field;
import java.util.List;

public interface AclEntryToSidsMapper {

    List<Sid> mapFieldToSids(Object object, Field field, AclAce aclEntry) throws IllegalAccessException;

}
