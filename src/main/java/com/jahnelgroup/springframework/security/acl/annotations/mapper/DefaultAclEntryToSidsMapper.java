package com.jahnelgroup.springframework.security.acl.annotations.mapper;

import com.jahnelgroup.springframework.security.acl.annotations.Ace;
import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.AclSid;
import com.jahnelgroup.springframework.security.acl.annotations.lookup.AclSidLookupStrategy;
import com.jahnelgroup.springframework.security.acl.annotations.util.ReflectionHelper;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;
import org.springframework.core.ResolvableType;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.ReflectionUtils;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;

public class DefaultAclEntryToSidsMapper implements AclEntryToSidsMapper {

    private AclSidLookupStrategy aclSidLookupStrategy;

    public DefaultAclEntryToSidsMapper(AclSidLookupStrategy aclSidLookupStrategy){
        this.aclSidLookupStrategy = aclSidLookupStrategy;
    }

    /**
     * This method is presumably called after finding a field annotated with {@link Ace}. We need
     * to map the value of that field to the Spring ACL SID's associated with it.
     *
     * In the simplest case the field is a String, Character or Number.
     *
     * The next easiest is if the field is a custom class like <pre>User</pre>.
     *
     * It gets more complicated if the field is a Collection or an Array[].
     *
     * @param object
     * @return
     */
    @Override
    public List<Sid> mapFieldToSids(Object object, Field field, Ace aclEntry) {
        try{
            Tuple<AclSid, List<Serializable>> aclSidListTuple = mapToSerializable(object, field);

            return mapToSids(isPrincipal(object, field, aclEntry, aclSidListTuple),
                    aclSidListTuple.second);

        }catch(Exception e){
            throw new AclRuntimeException(e);
        }
    }

    private boolean isPrincipal(Object object, Field field, Ace aclEntry, Tuple<AclSid, List<Serializable>> aclSidListTuple) throws Exception {
        if( aclSidListTuple.first == null ){
            if (aclEntry.sid() == null){
                throw new Exception(String.format("Unable to determine if sids are principal or granted authority " +
                        "for field %s for class %s", field.getName(), object.getClass().getCanonicalName()));
            }else{
                return aclEntry.sid().principal();
            }
        }else{
            return aclSidListTuple.first.principal();
        }
    }

    public Tuple<AclSid, List<Serializable>> mapToSerializable(Object object, Field field) throws IllegalAccessException {
        Object value = field.get(object);

        // String, Character or Number are a possible sid values
        if( value instanceof String || value instanceof Character || value instanceof Number ){
            return new Tuple<>(null, Arrays.asList((Serializable) value));
        }

        // Collection
        else if (ResolvableType.forField(field).asCollection() != ResolvableType.NONE){
            Collection collection = (Collection) value;

            // nothing to map
            if( collection.isEmpty() )
                return new Tuple<>(null, new LinkedList<>());

            Object o = collection.iterator().next();
            Triple<Object, Field, AclSid> result = aclSidLookupStrategy.lookup(o);

            if( result != null )
                return new Tuple<>(result.third, mapToValues(result.second, collection.iterator()));
        }

        // Array
        else if( ResolvableType.forField(field).isArray() ){
            Object[] arr = (Object[]) object;

            // nothing to map
            if( arr == null || arr.length == 0 )
                return new Tuple<>(null, new LinkedList<>());

            Triple<Object, Field, AclSid> result = aclSidLookupStrategy.lookup(arr[0]);

            if( result != null )
                return new Tuple<>(result.third, mapToValues(result.second, arr));
        }

        // Single Class property
        else{
            Triple<Object, Field, AclSid> result = aclSidLookupStrategy.lookup(value);

            if(result != null)
                return new Tuple<>(result.third, Arrays.asList((Serializable) value));
        }

        throw new AclRuntimeException(String.format("Unable to find @AclSid for field %s on class %s",
            field.getName(), object.getClass().getCanonicalName()));
    }

    private List<Serializable> mapToValues(Field field, Object[] objects) {
        return Arrays.stream(objects).map(obj -> {
            try {
                ReflectionUtils.makeAccessible(field);
                return (Serializable)field.get(obj);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }).collect(Collectors.toList());
    }

    private List<Serializable> mapToValues(Field field, Iterator iterator) {
        List<Serializable> values = new LinkedList<>();
        while(iterator.hasNext()){
            try {
                ReflectionUtils.makeAccessible(field);
                values.add((Serializable)field.get(iterator.next()));
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
        return values;
    }

    private List<Sid> mapToSids(boolean principal, List<Serializable> values){
        return values.stream().map(v -> principal ? new PrincipalSid(v.toString()) :
                new GrantedAuthoritySid(new SimpleGrantedAuthority((v.toString()))))
                .collect(Collectors.toList());
    }
}
