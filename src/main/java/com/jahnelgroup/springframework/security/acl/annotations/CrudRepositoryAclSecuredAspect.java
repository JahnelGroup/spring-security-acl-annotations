package com.jahnelgroup.springframework.security.acl.annotations;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.acls.model.MutableAclService;

import java.util.Iterator;

@Aspect
public class CrudRepositoryAclSecuredAspect extends AbstractAclSecuredAspect {

    private Logger logger = LoggerFactory.getLogger(CrudRepositoryAclSecuredAspect.class);

    public CrudRepositoryAclSecuredAspect(MutableAclService aclService,
            SidProvider sidProvider,
            AclAnnotationsConfigProperties properties) {
        super(aclService, sidProvider, properties);
        logger.info("CrudRepositoryAclSecuredAspect registered");
    }

    @Override
    @After("execution(* org.springframework.data.repository.CrudRepository.save(..)) && args(saved))")
    public void save(JoinPoint pjp, Object saved) throws IllegalAccessException {
        if ( saved == null ) return;

        if (saved instanceof Iterable<?> ){
            logger.info("CrudRepositoryAclSecuredAspect lst");
            Iterator iterator = ((Iterable) saved).iterator();
            while(iterator.hasNext()){
                updateAcl(iterator.next());
            }
        }else{
            logger.info("CrudRepositoryAclSecuredAspect one");
            updateAcl(saved);
        }
    }

}
