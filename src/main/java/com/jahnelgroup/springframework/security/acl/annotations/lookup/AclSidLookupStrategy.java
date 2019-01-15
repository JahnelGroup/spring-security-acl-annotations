package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.Ace;
import com.jahnelgroup.springframework.security.acl.annotations.AclSid;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Sid;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.List;

public interface AclSidLookupStrategy {

    List<Tuple<AclSid, List<Serializable>>> lookup(Object object) throws IllegalAccessException;

    List<Sid> mapToSids(Ace ace, Field field, Object object) throws IllegalAccessException;

}
