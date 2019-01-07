package com.jahnelgroup.springframework.security.acl.annotations;

import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;

public interface SidProvider {

    PrincipalSid getPrincipalSid(Object instance, Object sidField);
    GrantedAuthoritySid getGrantedAuthoritySid(Object instance, Object sidField);

}
