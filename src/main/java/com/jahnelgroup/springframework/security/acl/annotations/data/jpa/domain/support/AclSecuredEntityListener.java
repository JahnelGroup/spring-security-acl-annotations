package com.jahnelgroup.springframework.security.acl.annotations.data.jpa.domain.support;

import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.AclSecured;
import com.jahnelgroup.springframework.security.acl.annotations.config.AclSecuredConfiguration;
import com.jahnelgroup.springframework.security.acl.annotations.handler.AclSecuredHandler;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.util.Assert;

import javax.persistence.*;

/**
 * JPA entity listener to capture ACL information on persiting, updating and deleting entities.
 *
 * Inspired entirely by {@link org.springframework.data.jpa.domain.support.AuditingEntityListener}
 *
 * @author Steven Zgaljic
 */
@Configurable
public class AclSecuredEntityListener {


//    private static final Logger logger = LoggerFactory.getLogger(AclSecuredEntityListener.class);

    // TODO: For some reason these listeners are instantiated multiple times and the one that JPA uses doesn't
    // follow through with the dependency injections. Making this static gets around the problem for now.
    private static ObjectFactory<AclSecuredHandler> handler;

    private AclSecuredConfiguration config;
    private MutableAclService aclService;

    /**
     * Configures the {@link AclSecuredHandler} to be used to set the current ACL on the domain types touched.
     *
     * @param aclSecuredHandler must not be {@literal null}.
     */
    public void setAclSecuredHandler(ObjectFactory<AclSecuredHandler> aclSecuredHandler){
        Assert.notNull(aclSecuredHandler, "AclSecuredHandler must not be null!");
        this.handler = aclSecuredHandler;
    }

    /**
     * Configures the {@link AclSecuredConfiguration} to be used to set the current ACL on the domain types touched.
     *
     * @param aclAnnotationsConfig must not be {@literal null}.
     */
    public void setAclAnnotationsConfig(AclSecuredConfiguration aclAnnotationsConfig) {
        Assert.notNull(aclAnnotationsConfig, "AclSecuredConfiguration must not be null!");
        this.config = aclAnnotationsConfig;
    }

    /**
     * Configures the {@link MutableAclService} to be used to set the current ACL on the domain types touched.
     *
     * @param mutableAclService must not be {@literal null}.
     */
    public void setAclService(MutableAclService mutableAclService) {
        Assert.notNull(mutableAclService, "MutableAclService must not be null!");
        this.aclService = mutableAclService;
    }

    @PostPersist
    public void touchForCreate(Object target) {
        Assert.notNull(target, "Entity must not be null!");
        if ( target == null || target.getClass().getAnnotation(AclSecured.class) == null ) return;
        AclSecuredHandler object = handler.getObject();
        if(object != null){
            try {
                object.saveAcl(target);
            } catch (Exception e) {
                throw new AclRuntimeException(e.getMessage(), e);
            }
        }
    }

    @PostUpdate
    public void touchForUpdate(Object target) {
        Assert.notNull(target, "Entity must not be null!");
        if ( target == null || target.getClass().getAnnotation(AclSecured.class) == null ) return;
        AclSecuredHandler object = handler.getObject();
        if(object != null){
            try {
                object.saveAcl(target);
            } catch (Exception e) {
                throw new AclRuntimeException(e.getMessage(), e);
            }
        }
    }

    @PostRemove
    public void touchForRemove(Object target) {
        Assert.notNull(target, "Entity must not be null!");
        if ( target == null || target.getClass().getAnnotation(AclSecured.class) == null ) return;
        AclSecuredHandler object = handler.getObject();
        if(object != null){
            try {
                object.deleteAcl(target);
            } catch (Exception e) {
                throw new AclRuntimeException(e.getMessage(), e);
            }
        }
    }

}
