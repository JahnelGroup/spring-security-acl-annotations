package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclObjectId;
import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;

import java.lang.reflect.Field;

/**
 * Looks up the field annotated with {@link AclObjectId}.
 *
 * @author Steven Zgaljic
 */
public interface AclObjectIdLookupStrategy {

    /**
     * Returns a {@link Triple} referring to the field annotated with {@link AclObjectId} for
     * the provided Object. If no field is found then it will throw an {@link AclRuntimeException}.
     *
     * @param object
     * @return
     */
    Triple<Object, Field, AclObjectId> lookup(Object object);

}
