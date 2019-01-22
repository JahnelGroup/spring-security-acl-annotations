package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.AclAce;
import com.jahnelgroup.springframework.security.acl.annotations.AclSecured;
import com.jahnelgroup.springframework.security.acl.annotations.util.ReflectionHelper;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Default implementation of {@link AclAceLookupStrategy}.
 *
 * @author Steven Zgaljic
 */
public class DefaultAclAceLookupStrategy implements AclAceLookupStrategy{

    protected Map<Class, List<Tuple<AnnotatedElement, AclAce>>> cache = new HashMap<>();

    @Override
    public List<Tuple<AnnotatedElement, AclAce>> lookup(Object object) {
        List<Tuple<AnnotatedElement, AclAce>> result = new LinkedList<>();

        if( cache.containsKey(object.getClass()) ){
            result = cache.get(object.getClass());
        }else{
            synchronized (cache){
                if(!cache.containsKey(object.getClass())){
                    List<Tuple<AnnotatedElement, AclAce>> results = new LinkedList<>();
                    results.addAll(getAclAceFields(object));
                    results.addAll(getAclAceClasses(object));
                    cache.put(object.getClass(), result = results);
                }
            }
        }

        return result;
    }

    private List<Tuple<AnnotatedElement, AclAce>> getAclAceFields(Object object) {
        List<Triple<Object, Field, AclAce>> allAnnotatedFields = ReflectionHelper.findAllAnnotatedFields(object,
                AclAce.class);

        return allAnnotatedFields == null ? new LinkedList<>()
                : allAnnotatedFields.stream().map(ace -> new Tuple<>((AnnotatedElement)ace.second, ace.third)
            ).collect(Collectors.toList());
    }

    private List<Tuple<AnnotatedElement, AclAce>> getAclAceClasses(Object object) {
        List<Tuple<Class, AclSecured>> annotatedClasses = ReflectionHelper.findAnnotatedClasses(object, AclSecured.class);

        if( annotatedClasses == null )
            return new LinkedList<>();

        List<Tuple<AnnotatedElement, AclAce>> results = new LinkedList<>();

        for(Tuple<Class, AclSecured> el : annotatedClasses){
            if( el.second.aces() != null )
                for (AclAce aclAce: el.second.aces()) {
                    results.add(new Tuple<>(el.first, aclAce));
                }
        }

        return results;
    }

}
