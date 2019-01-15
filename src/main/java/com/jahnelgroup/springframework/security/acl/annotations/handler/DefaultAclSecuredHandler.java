package com.jahnelgroup.springframework.security.acl.annotations.handler;

import com.jahnelgroup.springframework.security.acl.annotations.Ace;
import com.jahnelgroup.springframework.security.acl.annotations.AclObjectId;
import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.lookup.*;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;
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

public class DefaultAclSecuredHandler implements AclSecuredHandler, InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(DefaultAclSecuredHandler.class);

    protected Map<Class, Field> idMap = new HashMap<>();
    protected Map<Class, List<Tuple<Ace, Field>>> aceMap = new HashMap<>();

    private AclObjectIdLookupStrategy aclObjectIdLookupStrategy = new DefaultAclObjectIdLookupStrategy();
    private AclParentLookupStrategy aclParentLookupStrategy = new DefaultAclParentLookupStrategy(aclObjectIdLookupStrategy);

    private AclSidLookupStrategy sidProvider = new DefaultAclSidLookupStrategy();


    private PermissionFactory permissionFactory = new DefaultPermissionFactory();
    private Optional<MutableAclService> aclService;

    public DefaultAclSecuredHandler(){
        logger.info("DefaultAclSecuredHandler loaded.");
    }

    /**
     * Sets the {@link AclSidLookupStrategy} to use during ACL evaluation. Defaults to {@link DefaultAclSidLookupStrategy}.
     *
     * @param sidProvider must not be {@literal null}.
     */
    public void setSidProvider(AclSidLookupStrategy sidProvider) {
        Assert.notNull(sidProvider, "AclSidLookupStrategy must not be null!");
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
                List<Tuple<Ace, Field>> aces = getAces(saved);

                ObjectIdentityImpl oi = new ObjectIdentityImpl(saved.getClass(),
                        aclObjectIdLookupStrategy.lookup(saved).third);

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
                Triple<Object, Field, Serializable> parentAcl = aclParentLookupStrategy.lookup(saved);
                if( parentAcl != null ){
                    ObjectIdentityImpl poi = new ObjectIdentityImpl(parentAcl.first.getClass(), parentAcl.third);
                    acl.setParent(aclService.readAclById(poi));
                    acl.setEntriesInheriting(true);
                }

                //
                // Access Control Entries (ACE's)
                //
                if( aces != null && !aces.isEmpty() ){
                    for(Tuple<Ace, Field> ace : aces){
                        for(Sid sid : getSid(ace, saved)){
                            for (String p : ace.first.permissions()) {
                                acl.insertAce(
                                        acl.getEntries().size(),
                                        getPermission(p),
                                        sid,
                                        ace.first.granting());
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

    @Override
    public void deleteAcl(Object deleted){
        aclService.ifPresent(aclService -> {
            try {
                ObjectIdentityImpl oi = new ObjectIdentityImpl(deleted.getClass(),
                        aclObjectIdLookupStrategy.lookup(deleted).third);

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
        return sidProvider.mapToSids(ace.first, ace.second, saved);
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

