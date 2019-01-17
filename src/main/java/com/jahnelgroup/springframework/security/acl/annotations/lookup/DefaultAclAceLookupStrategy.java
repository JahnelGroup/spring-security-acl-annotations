package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclAce;
import com.jahnelgroup.springframework.security.acl.annotations.util.ReflectionHelper;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class DefaultAclAceLookupStrategy implements AclAceLookupStrategy{

    protected Map<Class, List<Tuple<Field, AclAce>>> cache = new HashMap<>();

    @Override
    public Tuple<Object, List<Tuple<Field, AclAce>>> lookup(Object object) throws IllegalAccessException {
        List<Tuple<Field, AclAce>> result = new LinkedList<>();

        if( cache.containsKey(object.getClass()) ){
            result = cache.get(object.getClass());
        }else{
            List<Triple<Object, Field, AclAce>> allAnnotatedFields = ReflectionHelper.findAllAnnotatedFields(object,
                    AclAce.class);

            List<Tuple<Field, AclAce>> aces = allAnnotatedFields == null ? new LinkedList<>()
                    : allAnnotatedFields.stream().map(ace -> new Tuple<>(ace.second, ace.third)
                ).collect(Collectors.toList());

            synchronized (cache){
                if(!cache.containsKey(object.getClass())){
                    cache.put(object.getClass(), result = aces);
                }
            }
        }

        return new Tuple<>(object, result);
    }

}
