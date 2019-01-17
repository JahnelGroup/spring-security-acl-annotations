package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclObjectId;
import com.jahnelgroup.springframework.security.acl.annotations.AclParent;
import com.jahnelgroup.springframework.security.acl.annotations.AclSecured;
import com.jahnelgroup.springframework.security.acl.annotations.util.ReflectionHelper;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;
import org.springframework.util.ReflectionUtils;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.*;

public class DefaultAclParentLookupStrategy implements AclParentLookupStrategy {

    protected Map<Class, Field> cache = new HashMap<>();

    AclObjectIdLookupStrategy aclObjectIdLookupStrategy;

    public DefaultAclParentLookupStrategy(AclObjectIdLookupStrategy aclObjectIdLookupStrategy) {
        this.aclObjectIdLookupStrategy = aclObjectIdLookupStrategy;
    }

    @Override
    public Triple<Object, Field, AclParent> lookup(Object object) throws IllegalAccessException {
        // Find the @AclParent field.
        Triple<Object, Field, AclParent> parent = ReflectionHelper.findAnnotatedField(object, AclParent.class, (fieldObject, field) -> {
            if (fieldObject.getClass().getAnnotation(AclSecured.class) == null) {
                throw new RuntimeException(String.format("@Field %s for class %s is annotated as @AclParent " +
                                "but the class is not annotated with @AclSecured.",
                        field.getName(), object.getClass().getCanonicalName()));
            }
        });

        if( parent == null )
            return null;

        Triple<Object, Field, AclObjectId> objectId = aclObjectIdLookupStrategy.lookup(parent.first);
        if( object == null ){
            throw new RuntimeException(String.format("@Field %s for class %s is annotated as @AclParent " +
                            "but the class %s does not define @AclObjectId.",
                    parent.second.getName(), object.getClass().getCanonicalName(),
                    parent.first.getClass().getCanonicalName()));
        }

        return new Triple<>(objectId.first, objectId.second, parent.third);
    }

}
