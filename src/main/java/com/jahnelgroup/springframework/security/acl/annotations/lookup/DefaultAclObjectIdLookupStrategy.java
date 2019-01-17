package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclObjectId;
import com.jahnelgroup.springframework.security.acl.annotations.util.ReflectionHelper;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class DefaultAclObjectIdLookupStrategy implements AclObjectIdLookupStrategy {

    protected Map<Class, Tuple<Field, AclObjectId>> cache = new HashMap<>();

    @Override
    public Triple<Object, Field, AclObjectId> lookup(Object object) {
        Tuple<Field, AclObjectId> result = null;

        if( cache.containsKey(object.getClass()) ){
            result = cache.get(object.getClass());
        }else{
            Triple<Object, Field, AclObjectId> found = ReflectionHelper.findAnnotatedField(object,
                    AclObjectId.class, ReflectionHelper.IsSerializableConsumer());

            if( found == null ){
                throw new RuntimeException(String.format("Unable to find @AclObjectId for class %s",
                    object.getClass().getCanonicalName()));
            }

            synchronized (cache){
                if(!cache.containsKey(object.getClass())){
                    cache.put(object.getClass(), result = new Tuple<>(found.second, found.third));
                }
            }
        }

        return new Triple<>(object, result.first, result.second);
    }

}
