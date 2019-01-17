package com.jahnelgroup.springframework.security.acl.annotations.handler;

import com.jahnelgroup.springframework.security.acl.annotations.Ace;
import com.jahnelgroup.springframework.security.acl.annotations.AclObjectId;
import com.jahnelgroup.springframework.security.acl.annotations.AclParent;
import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.lookup.*;
import com.jahnelgroup.springframework.security.acl.annotations.mapper.AclEntryToSidsMapper;
import com.jahnelgroup.springframework.security.acl.annotations.mapper.DefaultAclEntryToSidsMapper;
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
    private AclSidLookupStrategy aclSidLookupStrategy = new DefaultAclSidLookupStrategy();
    private AclEntryToSidsMapper aclEntryToSidsMapper = new DefaultAclEntryToSidsMapper(aclSidLookupStrategy);

    private PermissionFactory permissionFactory = new DefaultPermissionFactory();
    private MutableAclService aclService;

    public DefaultAclSecuredHandler(){
        logger.info("DefaultAclSecuredHandler loaded.");
    }

    /**
     * Sets the {@link AclService} to use during ACL evaluation.
     * @param aclService
     */
    public void setAclService(MutableAclService aclService) {
        Assert.notNull(permissionFactory, "AclService must not be null!");
        this.aclService = aclService;
    }

    public void afterPropertiesSet() {
        if (aclService == null ) {
            // is it better to just warn and move on?
            throw new AclRuntimeException("No AclService set! Please review your configuration.");
        }
    }

    @Transactional
    @Override
    public void saveAcl(Object saved)  {
        try{
            MutableAcl acl = getAcl(saved);
            deleteAllAclEntries(acl, saved);
            setAclParentIfExists(acl, saved);
            insertAclEntries(acl, saved);
            aclService.updateAcl(acl);
        }catch(Exception e){
            throw new AclRuntimeException(e.getMessage(), e);
        }

    }

    private MutableAcl getAcl(Object saved) throws IllegalAccessException {
        Triple<Object, Field, AclObjectId> objectId = aclObjectIdLookupStrategy.lookup(saved);

        ObjectIdentityImpl oi = new ObjectIdentityImpl(saved.getClass(),
                (Serializable) objectId.second.get(objectId.first));

        MutableAcl acl;
        try{
            acl = (MutableAcl) aclService.readAclById(oi);
        }catch(NotFoundException nfe){
            acl = aclService.createAcl(oi);
        }

        return acl;
    }

    private void deleteAllAclEntries(MutableAcl acl, Object saved) {
        int size = acl.getEntries().size();
        for(int i=0; i<size; i++) acl.deleteAce(0);
    }

    private void setAclParentIfExists(MutableAcl acl, Object saved) throws IllegalAccessException {
        Triple<Object, Field, AclParent> parentAcl = aclParentLookupStrategy.lookup(saved);
        if( parentAcl != null ){
            ObjectIdentityImpl oi = new ObjectIdentityImpl(parentAcl.first.getClass(),
                    (Serializable)parentAcl.second.get(parentAcl.first));
            acl.setParent(aclService.readAclById(oi));
            acl.setEntriesInheriting(parentAcl.third.inheriting());
        }
    }

    private void insertAclEntries(MutableAcl acl, Object saved) throws IllegalAccessException {
        List<Tuple<Ace, Field>> aces = getAces(saved);
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
    }

    @Override
    public void deleteAcl(Object deleted){
        try {
            Triple<Object, Field, AclObjectId> objectId = aclObjectIdLookupStrategy.lookup(deleted);

            ObjectIdentityImpl oi = new ObjectIdentityImpl(deleted.getClass(),
                    (Serializable) objectId.second.get(objectId.first));
            try{
                aclService.deleteAcl(oi, true);
            }catch(ChildrenExistException nfe){
                // nothing to do
            }
        } catch (Exception e) {
            throw new AclRuntimeException(e);
        }

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

    protected List<Sid> getSid(Tuple<Ace, Field> ace, Object saved) throws IllegalAccessException {
        return aclEntryToSidsMapper.mapFieldToSids(saved, ace.second, ace.first);
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

