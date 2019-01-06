package com.jahnelgroup.springframework.security.acl;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.transaction.Transactional;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Aspect
abstract class AbstractAclSecuredAspect {

    private PermissionFactory permissionFactory = new DefaultPermissionFactory();
    private MutableAclService aclService;
    private AclAnnotationsConfigProperties properties;

    public AbstractAclSecuredAspect(MutableAclService aclService,
            AclAnnotationsConfigProperties properties) {

        this.aclService = aclService;
        this.properties = properties;
    }

    protected Map<Class, Tuple<AclOwner, Field>> ownerMap = new ConcurrentHashMap<>();
    protected Map<Class, List<Tuple<Ace, Field>>> aceMap = new ConcurrentHashMap<>();

    abstract void save(JoinPoint pjp, Object saved) throws IllegalAccessException;

    @Transactional
    protected void updateAcl(Object saved) throws IllegalAccessException {
        Tuple<AclOwner, Field> owner = getAclOwner(saved);
        List<Tuple<Ace, Field>> aces = getAces(saved);

        ObjectIdentityImpl oi = new ObjectIdentityImpl(saved.getClass(), (Serializable) owner.field.get(saved));

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
        // ACL Owning Sid
        //
        for (String p : owner.annotation.permissions()) {
            acl.insertAce(
                    acl.getEntries().size(),
                    getPermission(p),
                    getOwnerSid(owner, saved),
                    owner.annotation.granting());
        }

        //
        // Access Control Entries (ACE's)
        //
        if( aces != null && !aces.isEmpty() ){
            for(Tuple<Ace, Field> ace : aces){
                for (String p : ace.annotation.permissions()) {
                    acl.insertAce(
                            acl.getEntries().size(),
                            getPermission(p),
                            getAceSid(ace, saved),
                            ace.annotation.granting());
                }
            }
        }

        aclService.updateAcl(acl);
    }

    protected Tuple<AclOwner, Field> getAclOwner(Object saved) throws IllegalAccessException {
        Tuple<AclOwner, Field> tuple = null;

        if( ownerMap.containsKey(saved.getClass())){
            tuple = ownerMap.get(saved.getClass());
        }else{
            Field[] declaredFields = saved.getClass().getDeclaredFields();

            if( declaredFields != null ){
                for(int i=0; i<declaredFields.length; i++){
                    Field declaredField = declaredFields[i];
                    AclOwner ao = declaredField.getAnnotation(AclOwner.class);
                    if( ao != null ){
                        if(!(declaredField.get(saved) instanceof Serializable)){
                            throw new RuntimeException(String.format("Field %s for class %s must be Serializable",
                                    declaredField.getName(), saved.getClass().getCanonicalName()));
                        }
                        ownerMap.put(saved.getClass(), tuple = new Tuple<>(ao, declaredField));
                    }
                }
            }

            if( tuple == null ){
                throw new RuntimeException("Entity's marked with @AclSecured must have @AclOwner defined.");
            }
        }

        return tuple;
    }

    protected List<Tuple<Ace, Field>> getAces(Object saved) throws IllegalAccessException {
        List<Tuple<Ace, Field>> aces = null;

        if( aceMap.containsKey(saved.getClass())){
            aces = aceMap.get(saved.getClass());
        }else{
            Field[] declaredFields = saved.getClass().getDeclaredFields();

            if( declaredFields != null ){
                for(int i=0; i<declaredFields.length; i++){
                    Field declaredField = declaredFields[i];
                    Ace ace = declaredField.getAnnotation(Ace.class);
                    if( ace != null ){
                        if(aces == null) aces = new ArrayList<>();
                        if(!(declaredField.get(saved) instanceof Serializable)){
                            throw new RuntimeException(String.format("Field %s for class %s must be Serializable",
                                    declaredField.getName(), saved.getClass().getCanonicalName()));
                        }
                        aces.add(new Tuple<>(ace, declaredField));
                    }
                }

                if( !aceMap.containsKey(saved.getClass()) ){
                    aceMap.put(saved.getClass(), aces);
                }
            }
        }
        return aces;
    }

    private Sid getOwnerSid(Tuple<AclOwner, Field> owner, Object saved) throws IllegalAccessException {
        return owner.annotation.principal() ? new PrincipalSid(owner.field.get(saved).toString()) :
                new GrantedAuthoritySid(new SimpleGrantedAuthority((owner.field.get(saved).toString())));
    }

    private Sid getAceSid(Tuple<Ace, Field> owner, Object saved) throws IllegalAccessException {
        return owner.annotation.principal() ? new PrincipalSid(owner.field.get(saved).toString()) :
                new GrantedAuthoritySid(new SimpleGrantedAuthority((owner.field.get(saved).toString())));
    }

    // TODO: Cache
    private Permission getPermission(String perm){
        return permissionFactory.buildFromName(perm);
    }

}

class Tuple<X, Y> {
    public final X annotation;
    public final Y field;
    public Tuple(X annotation, Y field) {
        this.annotation = annotation;
        this.field = field;
    }
}
