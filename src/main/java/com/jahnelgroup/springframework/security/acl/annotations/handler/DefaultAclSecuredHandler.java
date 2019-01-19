package com.jahnelgroup.springframework.security.acl.annotations.handler;

import com.jahnelgroup.springframework.security.acl.annotations.*;
import com.jahnelgroup.springframework.security.acl.annotations.lookup.*;
import com.jahnelgroup.springframework.security.acl.annotations.mapper.AclAceToSidMapper;
import com.jahnelgroup.springframework.security.acl.annotations.mapper.DefaultAclAceToSidMapper;
import com.jahnelgroup.springframework.security.acl.annotations.util.Triple;
import com.jahnelgroup.springframework.security.acl.annotations.util.Tuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.model.*;
import org.springframework.util.Assert;

import javax.transaction.Transactional;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Default ACL secured handler to create, update and delete ACLs.
 *
 * @author Steven Zgaljic
 */
public class DefaultAclSecuredHandler implements AclSecuredHandler, InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(DefaultAclSecuredHandler.class);

    private PermissionFactory permissionFactory = new DefaultPermissionFactory();
    private MutableAclService aclService;

    private AclAceLookupStrategy aclAceLookupStrategy = new DefaultAclAceLookupStrategy();
    private AclObjectIdLookupStrategy aclObjectIdLookupStrategy = new DefaultAclObjectIdLookupStrategy();
    private AclParentLookupStrategy aclParentLookupStrategy = new DefaultAclParentLookupStrategy(aclObjectIdLookupStrategy);
    private AclSidLookupStrategy aclSidLookupStrategy = new DefaultAclSidLookupStrategy();
    private AclAceToSidMapper aclAceToSidMapper = new DefaultAclAceToSidMapper(aclSidLookupStrategy);
    private AclPermissionLookStrategy aclPermissionLookStrategy = new DefaultAclPermissionStrategy(permissionFactory);

    public DefaultAclSecuredHandler(){
        logger.info("DefaultAclSecuredHandler loaded.");
    }

    /**
     * Sets the {@link AclService} to use during ACL evaluation.
     *
     * @param aclService
     */
    @Override
    public void setAclService(MutableAclService aclService) {
        Assert.notNull(aclService, "AclService must not be null!");
        this.aclService = aclService;
    }

    /**
     * Sets the {@link PermissionFactory} to use during ACL evaluation.
     *
     * @param permissionFactory
     */
    public void setPermissionFactory(PermissionFactory permissionFactory) {
        Assert.notNull(permissionFactory, "PermissionFactory must not be null!");
        this.permissionFactory = permissionFactory;
    }

    /**
     * Sets the {@link AclAceLookupStrategy} to use during ACL evaluation.
     *
     * @param aclAceLookupStrategy
     */
    public void setAclAceLookupStrategy(AclAceLookupStrategy aclAceLookupStrategy) {
        Assert.notNull(aclAceLookupStrategy, "AclAceLookupStrategy must not be null!");
        this.aclAceLookupStrategy = aclAceLookupStrategy;
    }

    /**
     * Sets the {@link AclObjectIdLookupStrategy} to use during ACL evaluation.
     *
     * @param aclObjectIdLookupStrategy
     */
    public void setAclObjectIdLookupStrategy(AclObjectIdLookupStrategy aclObjectIdLookupStrategy) {
        Assert.notNull(aclObjectIdLookupStrategy, "AclObjectIdLookupStrategy must not be null!");
        this.aclObjectIdLookupStrategy = aclObjectIdLookupStrategy;
    }

    /**
     * Sets the {@link AclParentLookupStrategy} to use during ACL evaluation.
     *
     * @param aclParentLookupStrategy
     */
    public void setAclParentLookupStrategy(AclParentLookupStrategy aclParentLookupStrategy) {
        Assert.notNull(aclParentLookupStrategy, "AclParentLookupStrategy must not be null!");
        this.aclParentLookupStrategy = aclParentLookupStrategy;
    }

    /**
     * Sets the {@link AclSidLookupStrategy} to use during ACL evaluation.
     *
     * @param aclSidLookupStrategy
     */
    public void setAclSidLookupStrategy(AclSidLookupStrategy aclSidLookupStrategy) {
        Assert.notNull(aclSidLookupStrategy, "AclSidLookupStrategy must not be null!");
        this.aclSidLookupStrategy = aclSidLookupStrategy;
    }

    /**
     * Sets the {@link AclAceToSidMapper} to use during ACL evaluation.
     *
     * @param aclAceToSidMapper
     */
    public void setAclAceToSidMapper(AclAceToSidMapper aclAceToSidMapper) {
        Assert.notNull(aclAceToSidMapper, "AclAceToSidMapper must not be null!");
        this.aclAceToSidMapper = aclAceToSidMapper;
    }

    /**
     * Sets the {@link AclPermissionLookStrategy} to use during ACL evaluation.
     *
     * @param aclPermissionLookStrategy
     */
    public void setAclPermissionLookStrategy(AclPermissionLookStrategy aclPermissionLookStrategy) {
        Assert.notNull(aclPermissionLookStrategy, "AclPermissionLookStrategy must not be null!");
        this.aclPermissionLookStrategy = aclPermissionLookStrategy;
    }

    /**
     * Validates that all dependencies are set.
     */
    public void afterPropertiesSet() {
        if (aclService == null )
            throw new AclRuntimeException("No AclService set! Please review your configuration.");
        if (permissionFactory == null )
            throw new AclRuntimeException("No PermissionFactory set! Please review your configuration.");
        if (aclAceLookupStrategy == null )
            throw new AclRuntimeException("No AclAceLookupStrategy set! Please review your configuration.");
        if (aclObjectIdLookupStrategy == null )
            throw new AclRuntimeException("No AclObjectIdLookupStrategy set! Please review your configuration.");
        if (aclParentLookupStrategy == null )
            throw new AclRuntimeException("No AclParentLookupStrategy set! Please review your configuration.");
        if (aclSidLookupStrategy == null )
            throw new AclRuntimeException("No AclSidLookupStrategy set! Please review your configuration.");
        if (aclAceToSidMapper == null )
            throw new AclRuntimeException("No AclAceToSidMapper set! Please review your configuration.");
        if (aclPermissionLookStrategy == null )
            throw new AclRuntimeException("No AclPermissionLookStrategy set! Please review your configuration.");
    }

    /**
     * Creates a new ACL for the saved Object.
     *
     * @param saved
     */
    @Override
    public void createAcl(Object saved) {
        saveAcl(saved);
    }

    /**
     * Updates an existing ACL for the saved Object.
     *
     * @param saved
     */
    @Override
    public void updateAcl(Object saved) {
        saveAcl(saved);
    }

    /**
     * Creates a new ACL or updates an existing ACL for the saved Object.
     *
     * @param saved
     */
    @Transactional
    public void saveAcl(Object saved)  {
        try{
            MutableAcl acl = getAcl(saved);
            deleteAllAclEntries(acl);
            setAclParentIfExists(acl, saved);
            insertAclEntries(acl, saved);
            aclService.updateAcl(acl);
        }catch(Exception e){
            throw new AclRuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Returns a reference to the ACL for the provided Object. If no ACL is found then a new empty ACL will
     * be created and returned.
     *
     * The provided Object must satisfy these conditions:
     *
     * 1. The Object's class must be annotated with {@link AclSecured}
     * 2. The Object must have a single Serializable field annotated with {@link AclObjectId} somewhere in it's hierarchy.
     * 2. The Object must have a single Serializable field annotated with {@link AclSid} somewhere in it's hierarchy.
     * 3.
     *
     * @param object
     * @return
     * @throws IllegalAccessException
     */
    private MutableAcl getAcl(Object object) throws IllegalAccessException {
        Triple<Object, Field, AclObjectId> objectId = aclObjectIdLookupStrategy.lookup(object);

        ObjectIdentityImpl oi = new ObjectIdentityImpl(object.getClass(),
                (Serializable) objectId.second.get(objectId.first));

        MutableAcl acl;
        try{
            acl = (MutableAcl) aclService.readAclById(oi);
        }catch(NotFoundException nfe){
            acl = aclService.createAcl(oi);
        }

        return acl;
    }

    /**
     * Removes all AccessControlEntry's for the provided ACL.
     *
     * @param acl
     */
    private void deleteAllAclEntries(MutableAcl acl) {
        int size = acl.getEntries().size();
        for(int i=0; i<size; i++) acl.deleteAce(0);
    }

    /**
     * Inspects the provided Object for {@link AclParent} configurations and set the parent ACL if it exists.
     *
     * @param acl
     * @param object
     * @throws IllegalAccessException
     */
    private void setAclParentIfExists(MutableAcl acl, Object object) throws IllegalAccessException {
        Triple<Object, Field, AclParent> parentAcl = aclParentLookupStrategy.lookup(object);
        if( parentAcl != null ){
            ObjectIdentityImpl oi = new ObjectIdentityImpl(parentAcl.first.getClass(),
                    (Serializable)parentAcl.second.get(parentAcl.first));
            acl.setParent(aclService.readAclById(oi));
            acl.setEntriesInheriting(parentAcl.third.inheriting());
        }
    }

    /**
     * Lookup {@link AclAce} configurations for the provided Object and insert entries into the
     * ACL for each associated {@link AclSid}.
     *
     * @param acl
     * @param object
     * @throws IllegalAccessException
     */
    private void insertAclEntries(MutableAcl acl, Object object) throws IllegalAccessException {
        Map<Integer, Map<Integer, Boolean>> entries = new HashMap<>();
        for(Tuple<Field, AclAce> ace : getAces(object)){
            for(Sid sid : getSids(ace, object)){
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
    private boolean notDuplicatePermissionEntry(Integer sidHashcode, Integer permissionMask,
            Map<Integer, Map<Integer, Boolean>> entries){
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

    /**
     * Deletes the entire ACL for the provided Object.
     *
     * @param deleted
     */
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

    /**
     * Looks up the {@link AclAce} configurations for the provided Object and returns a List with the
     * reflected and associated annotation.
     *
     * @param saved
     * @return
     */
    protected List<Tuple<Field, AclAce>> getAces(Object saved) {
        List<Tuple<Field, AclAce>> aces = aclAceLookupStrategy.lookup(saved);

        if( aces == null || aces.isEmpty() )
            return new LinkedList<>();

        return aces;
    }

    /**
     * Maps the {@link AclAce} for the provided Object into a List of associated {@link Sid}'s.
     *
     * @param ace
     * @param saved
     * @return
     */
    protected List<Sid> getSids(Tuple<Field, AclAce> ace, Object saved) {
        List<Sid> sids = aclAceToSidMapper.mapFieldToSids(saved, ace.first, ace.second);

        if( sids == null || sids.isEmpty() )
            return new LinkedList<>();

        return sids;
    }

    /**
     * Uses the configured {@link PermissionFactory} to lookup {@link Permission} based on the permission name.
     *
     * @param perm
     * @return
     */
    private Permission getPermission(String perm){
        return permissionFactory.buildFromName(perm.toUpperCase());
    }

}

