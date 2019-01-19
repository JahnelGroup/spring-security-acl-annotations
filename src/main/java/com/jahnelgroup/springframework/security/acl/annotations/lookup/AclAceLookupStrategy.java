package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclAce;
import com.jahnelgroup.springframework.security.acl.annotations.AclSecured;
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
     * the provided Object, in addition to {@link AclAce}'s found at the class level on {@link AclSecured}. In the
     * case of a Class level {@link AclAce} the Field in the Tuple will be null.
     *
     * If nothing is found then an empty {@link List} is returned.
     *
     * @param object
     * @return empty {@link List} if no fields are found
     */
    List<Tuple<Field, AclAce>> lookup(Object object);

}
