package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclAce;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;

import java.lang.reflect.Field;
import java.util.List;

/**
 * Looks up fields annotated with {@link AclAce}.
 *
 * @author Steven Zgaljic
 */
public interface AclAceLookupStrategy {

    /**
     * Returns a {@link List} of {@link Tuple}'s referring to fields annotated with {@link AclAce} for
     * the provided Object. If no fields are found then an empty {@link List} is returned.
     *
     * @param object
     * @return empty {@link List} if no fields are found
     */
    List<Tuple<Field, AclAce>> lookup(Object object);

}
