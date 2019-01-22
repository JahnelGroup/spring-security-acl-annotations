package com.jahnelgroup.springframework.security.acl.annotations.mapper;

import com.jahnelgroup.springframework.security.acl.annotations.AclAce;
import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.AclSid;
import com.jahnelgroup.springframework.security.acl.annotations.lookup.AclSidLookupStrategy;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;
import org.springframework.core.ResolvableType;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.ReflectionUtils;

import java.io.Serializable;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Default implementation of {@link AclAceToSidMapper}.
 *
 * @author Steven Zgaljic
 */
@SuppressWarnings("Duplicates")
public class DefaultAclAceToSidMapper implements AclAceToSidMapper {

    private ClassAclAceToSidMapper classAclAceToSidMapper = new ClassAclAceToSidMapper();
    private SpelExpressionParser expressionParser = new SpelExpressionParser();
    private AclSidLookupStrategy aclSidLookupStrategy;

    public DefaultAclAceToSidMapper(AclSidLookupStrategy aclSidLookupStrategy){
        this.aclSidLookupStrategy = aclSidLookupStrategy;
    }

    /**
     * This method is presumably called after finding a field annotated with {@link AclAce}. We need
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
    public List<Sid> mapToSids(Object object, AnnotatedElement element, AclAce aclAce) {
        try{
            if( element instanceof Class ){
                return classAclAceToSidMapper.mapToSids(object, element, aclAce);
            }

            else if(element instanceof Field ){
                return mapField(object, (Field)element, aclAce);
            }

            else{
                throw new AclRuntimeException(String.format("Unable to derive sids from AnnotatedElement %s for " +
                        "Class %s", element, object.getClass().getCanonicalName()));
            }
        }catch(Exception e){
            throw new AclRuntimeException(e);
        }
    }

    private boolean hasSid(AclAce aclAce){
        return aclAce.sid() != null && aclAce.sid().length > 0;
    }

    public List<Sid> mapField(Object object, Field field, AclAce aclAce) throws IllegalAccessException {
        Object value = field.get(object);

        // String, Character or Number are a possible sid values
        if( value instanceof String || value instanceof Character || value instanceof Number ){

            if( aclAce.sid() == null )
                throw new AclRuntimeException(String.format("Unable to determine if sids are principal or granted authority " +
                        "for field %s for class %s. AclAce fields on String, Character or Number must supply the sid " +
                        "attribute.", field.getName(), object.getClass().getCanonicalName()));

            return mapToSids(aclAce.sid()[0].principal(), Arrays.asList((Serializable) value));
        }

        // Collection
        else if (ResolvableType.forField(field).asCollection() != ResolvableType.NONE){
            Collection collection = (Collection) value;

            // nothing to map
            if( collection.isEmpty() )
                return new LinkedList<>();

            List<Object> elementList = new ArrayList<>();
            Iterator it = collection.iterator();
            Object first = it.next();
            if( first instanceof String || first instanceof Character || first instanceof Number ){
                elementList.add(first);
                it.forEachRemaining(elementList::add);
            }else{
                Triple<Object, Field, AclSid> result = aclSidLookupStrategy.lookup(it);
                elementList.add(result.second.get(result.first));
                while(it.hasNext()){
                    result = aclSidLookupStrategy.lookup(it);
                    elementList.add(result.second.get(result.first));
                    aclSid = result.third;
                }
            }

            return mapToSids(aclSid.principal(), elementList);
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
                return new Tuple<>(result.third, Arrays.asList((Serializable) result.second.get(result.first)));
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

    private Object evaluate(String expression, Object object) {
        Expression exp = expressionParser.parseExpression(expression);
        EvaluationContext context = new StandardEvaluationContext(object);

        Object value = exp.getValue(context);
        if( value == null ){
            throw new RuntimeException(String.format("Unable to find AclSid for class %s with expression %s",
                    object.getClass().getCanonicalName(), expression));
        }

        return value;
    }
}
