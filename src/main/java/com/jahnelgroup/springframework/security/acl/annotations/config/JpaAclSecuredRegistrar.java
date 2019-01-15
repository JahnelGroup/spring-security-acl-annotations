package com.jahnelgroup.springframework.security.acl.annotations.config;

import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import com.jahnelgroup.springframework.security.acl.annotations.data.jpa.domain.support.AclSecuredBeanFactoryPostProcessor;
import com.jahnelgroup.springframework.security.acl.annotations.data.jpa.domain.support.AclSecuredEntityListener;
import com.jahnelgroup.springframework.security.acl.annotations.data.jpa.repository.config.EnableAclSecured;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.aspectj.AnnotationBeanConfigurerAspect;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.data.config.ParsingUtils;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.lang.annotation.Annotation;

import static com.jahnelgroup.springframework.security.acl.annotations.data.jpa.domain.support.AclSecuredBeanFactoryPostProcessor.BEAN_CONFIGURER_ASPECT_BEAN_NAME;

/**
 * {@link ImportBeanDefinitionRegistrar} to enable {@link EnableAclSecured} first.
 *
 * Derived and inspired by {@link org.springframework.data.jpa.repository.config.JpaAuditingRegistrar}
 *
 * @author Steven Zgaljic
 */
public class JpaAclSecuredRegistrar extends AclSecuredBeanDefinitionRegistrarSupport {

    private static final String BEAN_CONFIGURER_ASPECT_CLASS_NAME = "org.springframework.beans.factory.aspectj.AnnotationBeanConfigurerAspect";

    // from org.springframework.data.jpa.repository.config.BeanDefinitionNames
    public static final String JPA_MAPPING_CONTEXT_BEAN_NAME = "jpaMappingContext";

    @Override
    protected Class<? extends Annotation> getAnnotation() {
        return EnableAclSecured.class;
    }

    @Override
    protected String getAclSecuredHandlerBeanName() {
        return "jpaAclSecuredHandler";
    }

    @Override
    protected BeanDefinitionBuilder getAclSecuredHandlerBeanDefinitionBuilder(AclSecuredConfiguration configuration) {
        BeanDefinitionBuilder builder = super.getAclSecuredHandlerBeanDefinitionBuilder(configuration);
        return builder;
    }

    @Override
    public void registerBeanDefinitions(AnnotationMetadata annotationMetadata, BeanDefinitionRegistry registry) {

        Assert.notNull(annotationMetadata, "AnnotationMetadata must not be null!");
        Assert.notNull(registry, "BeanDefinitionRegistry must not be null!");

        registerBeanConfigurerAspectIfNecessary(registry);
        super.registerBeanDefinitions(annotationMetadata, registry);
        registerInfrastructureBeanWithId(
                BeanDefinitionBuilder.rootBeanDefinition(AclSecuredBeanFactoryPostProcessor.class).getRawBeanDefinition(),
                AclSecuredBeanFactoryPostProcessor.class.getName(), registry);
    }


    @Override
    protected void registerAclSecuredListenerBeanDefinition(BeanDefinition aclSecuredHandlerDefinition, BeanDefinitionRegistry registry) {
        if (!registry.containsBeanDefinition(JPA_MAPPING_CONTEXT_BEAN_NAME)) {
            throw new AclRuntimeException("Bean " + JPA_MAPPING_CONTEXT_BEAN_NAME + " must exist in order for AclSecured to work.");

            // Unable to register this because it's not public
            // registry.registerBeanDefinition(JPA_MAPPING_CONTEXT_BEAN_NAME, //
            //        new RootBeanDefinition(JpaMetamodelMappingContextFactoryBean.class));
        }

        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(AclSecuredEntityListener.class);
        builder.addPropertyValue("aclSecuredHandler",
                ParsingUtils.getObjectFactoryBeanDefinition(getAclSecuredHandlerBeanName(), null));
        registerInfrastructureBeanWithId(builder.getRawBeanDefinition(), AclSecuredEntityListener.class.getName(), registry);
    }

    /**
     * @param registry, the {@link BeanDefinitionRegistry} to be used to register the
     *          {@link AnnotationBeanConfigurerAspect}.
     */
    private void registerBeanConfigurerAspectIfNecessary(BeanDefinitionRegistry registry) {
        if (registry.containsBeanDefinition(BEAN_CONFIGURER_ASPECT_BEAN_NAME)) {
            return;
        }

        if (!ClassUtils.isPresent(BEAN_CONFIGURER_ASPECT_CLASS_NAME, getClass().getClassLoader())) {
            throw new BeanDefinitionStoreException(BEAN_CONFIGURER_ASPECT_CLASS_NAME + " not found. \n"
                    + "Could not configure Spring Acl Annotations because"
                    + " spring-aspects.jar is not on the classpath!\n"
                    + "If you want to use secured acl annotations please add spring-aspects.jar to the classpath.");
        }

        RootBeanDefinition def = new RootBeanDefinition();
        def.setBeanClassName(BEAN_CONFIGURER_ASPECT_CLASS_NAME);
        def.setFactoryMethodName("aspectOf");
        def.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

        registry.registerBeanDefinition(BEAN_CONFIGURER_ASPECT_BEAN_NAME,
                new BeanComponentDefinition(def, BEAN_CONFIGURER_ASPECT_BEAN_NAME).getBeanDefinition());
    }
}
