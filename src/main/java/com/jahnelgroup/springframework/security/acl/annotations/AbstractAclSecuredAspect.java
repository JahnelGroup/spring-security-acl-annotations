package com.jahnelgroup.springframework.security.acl.annotations;

import org.aspectj.lang.JoinPoint;
import org.springframework.core.ResolvableType;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.ReflectionUtils;

import javax.transaction.Transactional;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;

abstract class AbstractAclSecuredAspect {

    private PermissionFactory permissionFactory = new DefaultPermissionFactory();

    private MutableAclService aclService;
    private SidProvider sidProvider;
    private AclAnnotationsConfigProperties properties;

    public AbstractAclSecuredAspect(MutableAclService aclService,
            SidProvider sidProvider,
            AclAnnotationsConfigProperties properties) {
        this.aclService = aclService;
        this.sidProvider = sidProvider;
        this.properties = properties;
    }

    protected Map<Class, Field> idMap = new HashMap<>();
    protected Map<Class, List<Tuple<Ace, Field>>> aceMap = new HashMap<>();

    abstract void save(JoinPoint pjp, Object saved) throws IllegalAccessException;

    @Transactional
    protected void updateAcl(Object saved) throws IllegalAccessException {
        Field objectIdField = getObjectIdField(saved);
        List<Tuple<Ace, Field>> aces = getAces(saved);

        ObjectIdentityImpl oi = new ObjectIdentityImpl(saved.getClass(), (Serializable) objectIdField.get(saved));

        //
        // Access Control List
        //
        MutableAcl acl = null;
        try{
            acl = (MutableAcl) aclService.readAclById(oi);
        }catch(NotFoundException nfe){
            acl = aclService.createAcl(oi);
        }

        //
        // Access Control Entries (ACE's)
        //
        if( aces != null && !aces.isEmpty() ){
            for(Tuple<Ace, Field> ace : aces){
                for(Sid sid : getSid(ace, saved)){
                    for (String p : ace.annotation.permissions()) {
                        acl.insertAce(
                                acl.getEntries().size(),
                                getPermission(p),
                                sid,
                                ace.annotation.granting());
                    }
                }


            }
        }

        aclService.updateAcl(acl);
    }

    protected Field getObjectIdField(Object saved) throws IllegalAccessException {
        Field idField = null;
        if( idMap.containsKey(saved.getClass()) ){
            idField = idMap.get(saved.getClass());
        }else{
            List<Field> fields = getAllFields(new LinkedList<>(), saved.getClass());
            if( !fields.isEmpty() ) {
                for (Field field : fields) {
                    AclObjectId id = field.getAnnotation(AclObjectId.class);
                    if( id != null ){
                        ReflectionUtils.makeAccessible(field);
                        if(!(field.get(saved) instanceof Serializable)){
                            throw new RuntimeException(String.format("Field %s for class %s must be Serializable",
                                    field.getName(), saved.getClass().getCanonicalName()));
                        }
                        synchronized (idMap){
                            if(!idMap.containsKey(saved.getClass())){
                                idMap.put(saved.getClass(), idField = field);
                            }
                        }
                        break;
                    }
                }
            }
        }

        return idField;
    }

    protected List<Tuple<Ace, Field>> getAces(Object saved) throws IllegalAccessException {
        List<Tuple<Ace, Field>> aces = null;
        if( aceMap.containsKey(saved.getClass())){
            aces = aceMap.get(saved.getClass());
        }else{
            List<Field> fields = getAllFields(new LinkedList<>(), saved.getClass());
            if( !fields.isEmpty() ) {
                for (Field field : fields) {
                    Ace ace = field.getAnnotation(Ace.class);
                    if( ace != null ){
                        if(aces == null) aces = new ArrayList<>();
                        ReflectionUtils.makeAccessible(field);
                        aces.add(new Tuple<>(ace, field));
                    }
                }
                synchronized (aceMap){
                    if( !aceMap.containsKey(saved.getClass()) ){
                        aceMap.put(saved.getClass(), aces);
                    }
                }
            }
        }
        return aces;
    }

    private List<Sid> getSid(Tuple<Ace, Field> ace, Object saved) throws IllegalAccessException {
        Tuple<AclSid, List<Object>> sids = getSidValue(ace, saved);
        return sids.field.stream().map(sid -> sids.annotation.principal() ? new PrincipalSid(sid.toString()) :
                new GrantedAuthoritySid(new SimpleGrantedAuthority((sid.toString())))).collect(Collectors.toList());
    }

    private Tuple<AclSid, List<Object>> getSidValue(Tuple<Ace, Field> aceTuple, Object saved) throws IllegalAccessException {
        Ace ace = aceTuple.annotation;
        Object aceFieldValue = aceTuple.field.get(saved);

        // assuming the sid is the field itself ...
        if( aceFieldValue instanceof String || aceFieldValue instanceof Character || aceFieldValue instanceof Number ){
            throw new UnsupportedOperationException("AclSid cannot be a String, Character or Number yet.");
//            List<Object> sidValues = new ArrayList<>();
//            sidValues.add(aceFieldValue);
//            return new Tuple<>(null, sidValues); // TODO.... No @Sid in this case

        }

        // Array
        else if( ResolvableType.forField(aceTuple.field).isArray() ){
            throw new UnsupportedOperationException("AclSid cannot be an array[] yet.");
        }

        // Iterable
        else if (ResolvableType.forField(aceTuple.field).isInstance(Iterable.class)){
            if(ResolvableType.forField(aceTuple.field).hasGenerics()){

            }
        }

        // otherwise this is a custom class, go search for the sid
        else{
            List<Object> sidValues = new ArrayList<>();
            List<Field> fields = getAllFields(new LinkedList<>(), aceFieldValue.getClass());
            for(Field field : fields){
                AclSid sid = field.getAnnotation(AclSid.class);
                if( sid != null ){
                    ReflectionUtils.makeAccessible(field);
                    Object sidFieldValue = field.get(aceFieldValue);

                    sidValues.stream().forEach(s ->{
                        if(!(s instanceof Serializable)){
                            throw new RuntimeException(String.format("Field %s for class %s must be Serializable",
                                    field.getName(), aceFieldValue.getClass().getCanonicalName()));
                        }
                    });

                    return new Tuple<>(sid, sidValues);
                }
            }
        }

        throw new RuntimeException(String.format("Unable to derive sid for field %s on class %s",
                aceTuple.field.getName(), saved.getClass().getCanonicalName()));
    }

    // TODO: Cache
    private Permission getPermission(String perm){
        return permissionFactory.buildFromName(perm.toUpperCase());
    }

    private List<Field> getAllFields(List<Field> fields, Class<?> type) {
        fields.addAll(Arrays.asList(type.getDeclaredFields()));

        if (type.getSuperclass() != null) {
            getAllFields(fields, type.getSuperclass());
        }

        return fields;
    }

}

