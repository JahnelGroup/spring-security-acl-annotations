package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclParent;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;

import java.lang.reflect.Field;

/**
 * Looks up the field annotated with {@link AclParent}.
 *
 * @author Steven Zgaljic
 */
public interface AclParentLookupStrategy {

    /**
     * Returns a {@link Triple} referring to the field annotated with {@link AclParent} for
     * the provided Object. If no fields are found then {@literal null} is returned.
     *
     * @param object
     * @return {@literal null} if no field is found
     */
    Triple<Object, Field, AclParent> lookup(Object object);

}
