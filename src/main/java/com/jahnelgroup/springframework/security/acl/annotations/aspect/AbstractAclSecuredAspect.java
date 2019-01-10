package com.jahnelgroup.springframework.security.acl.annotations.aspect;

import com.jahnelgroup.springframework.security.acl.annotations.Ace;
import com.jahnelgroup.springframework.security.acl.annotations.AclObjectId;
import com.jahnelgroup.springframework.security.acl.annotations.config.AclAnnotationsConfigProperties;
import com.jahnelgroup.springframework.security.acl.annotations.sid.DefaultSidProvider;
import com.jahnelgroup.springframework.security.acl.annotations.sid.SidProvider;
import org.aspectj.lang.JoinPoint;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.model.*;
import org.springframework.util.ReflectionUtils;

import javax.transaction.Transactional;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.*;

abstract class AbstractAclSecuredAspect {

    private PermissionFactory permissionFactory = new DefaultPermissionFactory();

    private MutableAclService aclService;
    private SidProvider sidProvider = new DefaultSidProvider();
    private AclAnnotationsConfigProperties properties;

    public AbstractAclSecuredAspect(MutableAclService aclService,
            AclAnnotationsConfigProperties properties) {
        this.aclService = aclService;
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

        // Delete all current entries
        int size = acl.getEntries().size();
        for(int i=0; i<size; i++) acl.deleteAce(0);

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

    // TODO: Cache
    protected List<Sid> getSid(Tuple<Ace, Field> ace, Object saved) throws IllegalAccessException {
        return sidProvider.mapToSids(ace.annotation, ace.field, saved);
    }

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

