package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclObjectId;
import com.jahnelgroup.springframework.security.acl.annotations.util.ReflectionHelper;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class DefaultAclObjectIdLookupStrategy implements AclObjectIdLookupStrategy {

    protected Map<Class, Field> cache = new HashMap<>();

    @Override
    public Triple<Object, Field, Serializable> lookup(Object object) throws IllegalAccessException {
        Field foundField = null;

        if( cache.containsKey(object.getClass()) ){
            foundField = cache.get(object.getClass());
        }else{

            Triple<Object, Field, AclObjectId> found = ReflectionHelper.findAnnotatedField(object,
                    AclObjectId.class, ReflectionHelper.IsSerializableConsumer());

            synchronized (cache){
                if(!cache.containsKey(object.getClass())){
                    cache.put(object.getClass(), foundField = found.second);
                }
            }
        }

        return new Triple<>(object, foundField, (Serializable)foundField.get(object));
    }

}
