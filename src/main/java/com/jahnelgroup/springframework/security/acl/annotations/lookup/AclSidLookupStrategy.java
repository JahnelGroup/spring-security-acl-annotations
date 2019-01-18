package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.AclSid;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;

import java.lang.reflect.Field;

/**
 * Looks up the field annotated with {@link AclSid}.
 *
 * @author Steven Zgaljic
 */
public interface AclSidLookupStrategy {

    /**
     * Returns a {@link Triple} referring to the field annotated with {@link AclSid} for
     * the provided Object. If no field is found then it will throw an {@link AclRuntimeException}.
     *
     * @param object
     * @return
     */
    Triple<Object, Field, AclSid> lookup(Object object);

}
