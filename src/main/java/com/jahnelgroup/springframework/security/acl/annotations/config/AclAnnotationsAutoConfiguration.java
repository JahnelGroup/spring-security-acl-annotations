package com.jahnelgroup.springframework.security.acl.annotations.config;

import com.jahnelgroup.springframework.security.acl.annotations.aspect.CrudRepositoryAclSecuredAspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
//        private SidProvider sidProvider;
        private final AclAnnotationsConfigProperties properties;

        public AclAnnotationsConfig(MutableAclService aclService,
                //PermissionFactory permissionFactory,
//                                    SidProvider sidProvider,
                AclAnnotationsConfigProperties properties){
            this.aclService = aclService;
//            this.sidProvider = sidProvider;
//            this.permissionFactory = permissionFactory;
            this.properties = properties;
        }

        @Bean
        public CrudRepositoryAclSecuredAspect aclSecuredAspect(){
            return new CrudRepositoryAclSecuredAspect(aclService, properties);
        }

    }

}
