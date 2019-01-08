package com.jahnelgroup.springframework.security.acl.annotations.sid;

import com.jahnelgroup.springframework.security.acl.annotations.Ace;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Sid;

import java.lang.reflect.Field;
import java.util.List;

public interface SidProvider {

    List<Sid> mapToSids(Ace ace, Field field, Object object) throws IllegalAccessException;

}
