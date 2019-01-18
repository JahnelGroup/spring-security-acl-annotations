package com.jahnelgroup.springframework.security.acl.annotations.mapper;

import com.jahnelgroup.springframework.security.acl.annotations.AclAce;
import com.jahnelgroup.springframework.security.acl.annotations.AclSid;
import org.springframework.security.acls.model.Sid;

import java.lang.reflect.Field;
import java.util.List;

/**
 * Maps a field annotated with {@link AclAce} to a list of associated {@link Sid}'s.
 *
 * @author Steven Zgaljic
 */
public interface AclEntryToSidsMapper {

    /**
     * This method is intended to be called after finding a field annotated with {@link AclAce}. It will
     * map the value of that field to a list of {@link Sid}'s associated with it. There are three four potential cases:
     *
     * Case 1:
     *      In the simplest case the field is a String, Character or Number.
     *
     * Case 2:
     *      The next easiest is if the field is a custom class like <pre>User</pre>. In this case it will look
     *      for a field annotated with {@link AclSid} in the class and return a list with that single element.
     *
     * Case 3:
     *      {@link AclAce} is annotated on a {@link java.util.Collection} like an {@link java.util.ArrayList}. In this
     *      case we take the first element in the list and look up the class then perform the same logic as in Case 2,
     *      the only difference is that we collect all the {@link AclSid}'s for each element in the Collection. If
     *      the Collection is null or empty then an empty {@link List} will be returned.
     *
     * Case 4:
     *      Same as Case 3 but for Array's.
     *
     * @param object
     * @param field
     * @param aclEntry
     * @return
     */
    List<Sid> mapFieldToSids(Object object, Field field, AclAce aclEntry);

}
