package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclSid;
import com.jahnelgroup.springframework.security.acl.annotations.util.ReflectionHelper;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link AclSidLookupStrategy}.
 *
 * @author Steven Zgaljic
 */
public class DefaultAclSidLookupStrategy implements AclSidLookupStrategy {

    protected Map<Class, Tuple<Field, AclSid>> cache = new HashMap<>();

    @Override
    public Triple<Object, Field, AclSid> lookup(Object object) {
        Tuple<Field, AclSid> result = null;

        if( cache.containsKey(object.getClass()) ){
            result = cache.get(object.getClass());
        }else{
            Triple<Object, Field, AclSid> found = ReflectionHelper.findAnnotatedField(object,
                    AclSid.class, ReflectionHelper.IsSerializableConsumer());

            if( found == null ){
                throw new RuntimeException(String.format("Unable to find @AclSid for class %s",
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
