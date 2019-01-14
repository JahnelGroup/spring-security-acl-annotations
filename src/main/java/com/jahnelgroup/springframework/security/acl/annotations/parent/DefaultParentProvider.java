package com.jahnelgroup.springframework.security.acl.annotations.parent;

import com.jahnelgroup.springframework.security.acl.annotations.AclObjectId;
import com.jahnelgroup.springframework.security.acl.annotations.AclParent;
import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.handler.Tuple;
import org.springframework.util.ReflectionUtils;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.*;

public class DefaultParentProvider implements ParentProvider {

    protected Map<Class, Field> parentMap = new HashMap<>();

    @Override
    public Tuple<Class, Serializable> getParentObjectIdentity(Object target) throws IllegalAccessException {
        List<Field> fields = getAllFields(new LinkedList<>(), target.getClass());
        if( !fields.isEmpty() ) {
            for (Field field : fields) {
                AclParent parent = field.getAnnotation(AclParent.class);
                if( parent != null ){
                    ReflectionUtils.makeAccessible(field);
                    Object value = field.get(target);
                    if(!(field.get(value) instanceof Serializable)){
                        throw new RuntimeException(String.format("Field %s for class %s must be Serializable",
                                field.getName(), value.getClass().getCanonicalName()));
                    }
                    return getParentObjectIdentityValue(value.getClass(), value);
                }
            }
        }

        return null;
    }

    private Tuple<Class, Serializable> getParentObjectIdentityValue(Class<?> clazz, Object saved) throws IllegalAccessException {
        List<Field> fields = getAllFields(new LinkedList<>(), clazz);
        if( !fields.isEmpty() ) {
            for (Field field : fields) {
                AclObjectId id = field.getAnnotation(AclObjectId.class);
                if( id != null ){
                    ReflectionUtils.makeAccessible(field);
                    Object aclParentId = field.get(saved);
                    if(!(aclParentId instanceof Serializable)){
                        throw new RuntimeException(String.format("Field %s for class %s must be Serializable",
                                field.getName(), saved.getClass().getCanonicalName()));
                    }
                    return new Tuple<>(aclParentId.getClass(), (Serializable) aclParentId);
                }
            }
        }
        return null;
    }


    private List<Field> getAllFields(List<Field> fields, Class<?> type) {
        fields.addAll(Arrays.asList(type.getDeclaredFields()));

        if (type.getSuperclass() != null) {
            getAllFields(fields, type.getSuperclass());
        }
        return fields;
    }


}
