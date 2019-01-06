package com.jahnelgroup.springframework.security.acl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.model.MutableAclService;

/**
 * Spring Acl Annotations Auto Configuration
 */
@Configuration
//@ConditionalOnBean({MutableAclService.class, PermissionFactory.class})
public class AclAnnotationsAutoConfiguration {

    private Logger logger = LoggerFactory.getLogger(AclAnnotationsAutoConfiguration.class);

    @Configuration
    //@ConditionalOnBean({MutableAclService.class, PermissionFactory.class})
    @EnableConfigurationProperties({AclAnnotationsConfigProperties.class})
    public static class AclAnnotationsConfig {

        private MutableAclService aclService;
//        private PermissionFactory permissionFactory;
        private final AclAnnotationsConfigProperties properties;

        public AclAnnotationsConfig(MutableAclService aclService,
                //PermissionFactory permissionFactory,
                AclAnnotationsConfigProperties properties){
            this.aclService = aclService;
//            this.permissionFactory = permissionFactory;
            this.properties = properties;
        }

        @Bean
        public CrudRepositoryAclSecuredAspect aclSecuredAspect(){
            return new CrudRepositoryAclSecuredAspect(aclService, properties);
        }

    }

}
