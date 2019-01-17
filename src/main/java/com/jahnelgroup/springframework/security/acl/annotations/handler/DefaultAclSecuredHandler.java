package com.jahnelgroup.springframework.security.acl.annotations.handler;

import com.jahnelgroup.springframework.security.acl.annotations.AclAce;
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

import javax.transaction.Transactional;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.*;

public class DefaultAclSecuredHandler implements AclSecuredHandler, InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(DefaultAclSecuredHandler.class);

    private AclAceLookupStrategy aclAceLookupStrategy = new DefaultAclAceLookupStrategy();
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
        Map<Integer, Map<Integer, Boolean>> entries = new HashMap<>();
        for(Tuple<Field, AclAce> ace : getAces(saved)){
            for(Sid sid : getSids(ace, saved)){
                for (String p : ace.second.permissions()) {
                    Permission permission = getPermission(p);
                    if(notDuplicatePermissionEntry(sid.hashCode(), permission.getMask(), entries))
                        acl.insertAce(
                            acl.getEntries().size(),
                            getPermission(p),
                            sid,
                            ace.second.granting());
                }
            }
        }
    }

    /**
     * Return true if this sid/permission combination is NOT a duplicate based on the entries map provided.
     *
     * @param sidHashcode
     * @param permissionMask
     * @param entries
     * @return
     */
    private boolean notDuplicatePermissionEntry(Integer sidHashcode, Integer permissionMask, Map<Integer, Map<Integer, Boolean>> entries){
        if(entries.containsKey(sidHashcode) ){
            if(entries.get(sidHashcode).containsKey(permissionMask))
                return false;
            else
                entries.get(sidHashcode).put(permissionMask, true);
        }else{
            entries.put(sidHashcode, new HashMap<>());
            entries.get(sidHashcode).put(permissionMask, true);
        }
        return true;
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

    protected List<Tuple<Field, AclAce>> getAces(Object saved) throws IllegalAccessException {
        Tuple<Object, List<Tuple<Field, AclAce>>> result = aclAceLookupStrategy.lookup(saved);

        if( result == null || result.second == null || result.second.isEmpty() )
            return new LinkedList<>();

        return result.second;
    }

    protected List<Sid> getSids(Tuple<Field, AclAce> ace, Object saved) throws IllegalAccessException {
        return aclEntryToSidsMapper.mapFieldToSids(saved, ace.first, ace.second);
    }

    private Permission getPermission(String perm){
        return permissionFactory.buildFromName(perm.toUpperCase());
    }

}

