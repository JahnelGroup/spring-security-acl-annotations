package com.jahnelgroup.springframework.security.acl.annotations.mapper;

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;

import org.springframework.core.ResolvableType;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.jahnelgroup.springframework.security.acl.annotations.AclAce;
import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.AclSid;
import com.jahnelgroup.springframework.security.acl.annotations.lookup.AclSidLookupStrategy;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;

@SuppressWarnings("Duplicates")
public class ClassAclAceToSidMapper {

    private SpelExpressionParser expressionParser = new SpelExpressionParser();

    private AclSidLookupStrategy aclSidLookupStrategy;

    public ClassAclAceToSidMapper(AclSidLookupStrategy aclSidLookupStrategy){
        this.aclSidLookupStrategy = aclSidLookupStrategy;
    }

    public List<Sid> mapToSids(Object object, AnnotatedElement element, AclAce aclAce) throws IllegalAccessException {
        List<Sid> sids = new LinkedList<>();

        if( element instanceof Class ){
            if( hasSid(aclAce) ){
                for (AclSid aclSid:aclAce.sid()) {
                    // must use SpEL if annotated on a class
                    sids.addAll(mapValue(evaluate(aclSid.expression(), object), aclAce, aclSid));
                }
            }
        }

        return sids;
    }

    private boolean hasSid(AclAce aclAce){
        return aclAce.sid() != null && aclAce.sid().length > 0;
    }

    public List<Sid> mapValue(Object value, AclAce aclAce, AclSid aclSid) throws IllegalAccessException {

        if( value == null )
            return new LinkedList<>();

        // String, Character or Number are a possible sid values
        if( value instanceof String || value instanceof Character || value instanceof Number ){
            return mapToSids(aclSid.principal(), Arrays.asList(value));
        }

        // Collection
        else if (ResolvableType.forInstance(value).asCollection() != ResolvableType.NONE){
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
        else if( ResolvableType.forInstance(value).isArray() ){
            Object[] arr = (Object[]) value;

            // nothing to map
            if( arr == null || arr.length == 0 )
                return new LinkedList<>();

            List<Object> elementList = new ArrayList<>();
            Object first = arr[0];
            if( first instanceof String || first instanceof Character || first instanceof Number ){
                elementList.addAll(Arrays.asList(arr));
            }else{
                for(Object it: arr){
                    Triple<Object, Field, AclSid> result = aclSidLookupStrategy.lookup(it);
                    elementList.add(result.second.get(result.first));
                    aclSid = result.third;
                }
            }

            return mapToSids(aclSid.principal(), Arrays.asList(arr));
        }

        // Single Class property
        else{
            Triple<Object, Field, AclSid> result = aclSidLookupStrategy.lookup(value);

            if(result != null)
                return mapToSids(aclSid.principal(), Arrays.asList(result.second.get(result.first)));
        }

        throw new AclRuntimeException(String.format("Unable to find AclSid for class %s",
                value.getClass().getCanonicalName()));
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

    private List<Sid> mapToSids(boolean principal, List<Object> values){
        return values.stream().map(v -> principal ? new PrincipalSid(v.toString()) :
                new GrantedAuthoritySid(new SimpleGrantedAuthority((v.toString()))))
                .collect(Collectors.toList());
    }

}
