package com.jahnelgroup.springframework.security.acl.annotations.lookup;

import com.jahnelgroup.springframework.security.acl.annotations.Ace;
import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.AclSid;
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

public class DefaultAclSidLookupStrategy implements AclSidLookupStrategy {

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


    ///
    // THIS ACTUALLY NEEDS TO CHANGE.... ASSUME IT"S CALLED ONCE FOR EACH CLASS / SID
    // THE LOOP IS DONE ELSEWHERE
    //
    public List<Tuple<AclSid, List<Serializable>>> lookup(Object object) {
        List<Triple<Object, Field, AclSid>> results = ReflectionHelper.findAllAnnotatedFields(object, AclSid.class);

        if( results == null || results.isEmpty() )
            throw new AclRuntimeException(String.format("Unable to derive @AclSid's for class %s",
                    object.getClass().getCanonicalName()));

        return results.stream().map(this::mapToSerializable).collect(Collectors.toList());
    }

    public List<Tuple<AclSid, List<Serializable>>> mapToSerializable(Triple<Object, Field, AclSid> root) {
        Object value = null;
        try{
            value = root.second.get(root.first);

            // String, Character or Number are a possible sid values
            if( value instanceof String || value instanceof Character || value instanceof Number ){
                return new Triple<>(root.first, root.second, Arrays.asList((Serializable) value));
            }

            // Collection
            if (ResolvableType.forField(root.second).asCollection() != ResolvableType.NONE){

            }

            // Array
            else if( ResolvableType.forField(root.second).isArray() ){

            }

            // Single Class property
            else{
                Triple<Object, Field, List<Serializable>> sidField = mapClass(root);

                if(sidField != null)
                    return new Triple<>(sidField.first, sidField.second,
                            Arrays.asList((Serializable) sidField.second.get(sidField.first)));
            }
        }catch(Exception e){
            throw new AclRuntimeException(e);
        }

        throw new RuntimeException(String.format("Unable to find the @AclSid from class %s",
                root.first.getClass().getCanonicalName()));
    }

    private Triple<Object, Field, List<Serializable>> mapClass(Triple<Object, Field, AclSid> root) throws IllegalAccessException {
        Triple<Object, Field, AclSid> sidField = ReflectionHelper.findAnnotatedField(
                root.first, AclSid.class, ReflectionHelper.IsSerializableConsumer());

        if(sidField != null)
            return new Triple<>(sidField.first, sidField.second,
                    Arrays.asList((Serializable) sidField.second.get(sidField.first)));

        return null;
    }

    @Override
    public List<Sid> mapToSids(Ace ace, Field field, Object object) throws IllegalAccessException {
        Object value = field.get(object);

        // Found it!
        if( value instanceof String || value instanceof Character || value instanceof Number ){
            return mapToSids(ace.sid().principal(), Arrays.asList(value));
        }

        // Collection
        if (ResolvableType.forField(field).asCollection() != ResolvableType.NONE){
            Collection collection = (Collection) value;

            // nothing to map
            if( collection.isEmpty() ){
                return new LinkedList<>();
            }

            Object o = collection.iterator().next();
            List<Field> fields = ReflectionHelper.getAllFields(new LinkedList<>(), o.getClass());
            for(Field f : fields){
                AclSid aclSid = f.getAnnotation(AclSid.class);
                if( aclSid != null ){
                    return mapToSids(aclSid.principal(), mapToValues(f, collection.iterator()));
                }
            }

            throw new RuntimeException(String.format("Unable to find the AclSid from class %s", o.getClass().getCanonicalName()));
        }

        // Array
        else if( ResolvableType.forField(field).isArray() ){
            Object[] arr = (Object[]) object;

            // nothing to map
            if( arr == null || arr.length == 0 )
                return new LinkedList<>();

            List<Field> fields = ReflectionHelper.getAllFields(new LinkedList<>(), arr[0].getClass());
            for(Field f : fields){
                AclSid aclSid = f.getAnnotation(AclSid.class);
                if( aclSid != null ){
                    return mapToSids(aclSid.principal(), mapToValues(f, arr));
                }
            }

            throw new RuntimeException(String.format("Unable to find the AclSid from class %s", arr[0].getClass().getCanonicalName()));
        }

        else{
            List<Field> fields = ReflectionHelper.getAllFields(new LinkedList<>(), value.getClass());
            for(Field f : fields){
                AclSid aclSid = f.getAnnotation(AclSid.class);
                if( aclSid != null ){
                    return mapToSids(aclSid.principal(), Arrays.asList(mapToValue(f, value)));
                }
            }

            throw new RuntimeException(String.format("Unable to find the AclSid from class %s", object.getClass().getCanonicalName()));
        }
    }

    private List<Object> mapToValues(Field field, Object[] objects) {
        return Arrays.stream(objects).map(obj -> {
            try {
                ReflectionUtils.makeAccessible(field);
                return field.get(obj);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }).collect(Collectors.toList());
    }

    private List<Object> mapToValues(Field field, Iterator iterator) {
        List<Object> values = new LinkedList<>();
        while(iterator.hasNext()){
            try {
                ReflectionUtils.makeAccessible(field);
                values.add(field.get(iterator.next()));
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
        return values;
    }

    private Object mapToValue(Field field, Object object) {
        ReflectionUtils.makeAccessible(field);
        try {
            return field.get(object);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private List<Sid> mapToSids(boolean principal, List<Object> values){
        return values.stream().map(v -> principal ? new PrincipalSid(v.toString()) :
                new GrantedAuthoritySid(new SimpleGrantedAuthority((v.toString()))))
                .collect(Collectors.toList());
    }
}
