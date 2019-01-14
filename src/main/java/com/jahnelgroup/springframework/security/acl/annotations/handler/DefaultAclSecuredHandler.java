package com.jahnelgroup.springframework.security.acl.annotations.handler;

import com.jahnelgroup.springframework.security.acl.annotations.Ace;
import com.jahnelgroup.springframework.security.acl.annotations.AclObjectId;
import com.jahnelgroup.springframework.security.acl.annotations.AclParent;
import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.config.AclSecuredConfiguration;
import com.jahnelgroup.springframework.security.acl.annotations.parent.DefaultParentProvider;
import com.jahnelgroup.springframework.security.acl.annotations.parent.ParentProvider;
import com.jahnelgroup.springframework.security.acl.annotations.sid.DefaultSidProvider;
import com.jahnelgroup.springframework.security.acl.annotations.sid.SidProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.model.*;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;

import javax.transaction.Transactional;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.*;
import java.util.function.Consumer;

public class DefaultAclSecuredHandler implements AclSecuredHandler, InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(DefaultAclSecuredHandler.class);

    protected Map<Class, Field> idMap = new HashMap<>();
    protected Map<Class, List<Tuple<Ace, Field>>> aceMap = new HashMap<>();

    private SidProvider sidProvider = new DefaultSidProvider();
    private ParentProvider parentProvider = new DefaultParentProvider();

    private PermissionFactory permissionFactory = new DefaultPermissionFactory();
    private Optional<MutableAclService> aclService;

    public DefaultAclSecuredHandler(){
        logger.info("DefaultAclSecuredHandler loaded.");
    }

    /**
     * Sets the {@link SidProvider} to use during ACL evaluation. Defaults to {@link DefaultSidProvider}.
     *
     * @param sidProvider must not be {@literal null}.
     */
    public void setSidProvider(SidProvider sidProvider) {
        Assert.notNull(sidProvider, "SidProvider must not be null!");
        this.sidProvider = sidProvider;
    }

    /**
     * Sets the {@link PermissionFactory} to use during ACL evaluation. Defaults to {@link DefaultPermissionFactory}.
     *
     * @param permissionFactory must not be {@literal null}.
     */
    public void setPermissionFactory(PermissionFactory permissionFactory) {
        Assert.notNull(permissionFactory, "PermissionFactory must not be null!");
        this.permissionFactory = permissionFactory;
    }

    /**
     * Sets the {@link AclService} to use during ACL evaluation.
     * @param aclService
     */
    public void setAclService(Optional<MutableAclService> aclService) {
        Assert.notNull(permissionFactory, "AclService must not be null!");
        this.aclService = aclService;
    }

    public void afterPropertiesSet() {
        if (!aclService.isPresent()) {
            // is it better to just warn and move on?
            throw new AclRuntimeException("No AclService set! Please review your configuration.");
        }
    }

    @Transactional
    @Override
    public void saveAcl(Object saved)  {
        aclService.ifPresent(aclService -> {
            try{
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

                // Set parent if it exists
                Tuple<Class, Serializable> parentAcl = parentProvider.getParentObjectIdentity(saved);
                if( parentAcl != null ){
                    ObjectIdentityImpl poi = new ObjectIdentityImpl(parentAcl.annotation, parentAcl.field);
                    acl.setParent(aclService.readAclById(poi));
                    acl.setEntriesInheriting(true);
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
            }catch(Exception e){
                throw new AclRuntimeException(e.getMessage(), e);
            }
        });

    }

    @Transactional
    @Override
    public void saveAcl(Iterable<?> saved){
        for(Object s : saved) saveAcl(s);
    }

    @Override
    public void deleteAcl(Object deleted){
        aclService.ifPresent(aclService -> {
            try {
                Field objectIdField = getObjectIdField(deleted);
                ObjectIdentityImpl oi = new ObjectIdentityImpl(deleted.getClass(), (Serializable) objectIdField.get(deleted));

                try{
                    aclService.deleteAcl(oi, true);
                }catch(ChildrenExistException nfe){
                    // nothing to do
                }
            } catch (Exception e) {
                throw new AclRuntimeException(e.getMessage(), e);
            }
        });
    }

    @Override
    public void deleteAcl(Iterable<?> deleted){
        for(Object d : deleted) deleteAcl(d);
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

