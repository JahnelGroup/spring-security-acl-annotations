package com.jahnelgroup.springframework.security.acl.annotations.config;

import com.jahnelgroup.springframework.security.acl.annotations.handler.AclSecuredHandler;

import com.jahnelgroup.springframework.security.acl.annotations.handler.DefaultAclSecuredHandler;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.Assert;
import java.lang.annotation.Annotation;

/**
 * A {@link ImportBeanDefinitionRegistrar} that serves as a base class for store specific implementations for
 * configuring acl secured support. Registers a {@link AclSecuredHandler} based on the provided configuration(
 * {@link AclSecuredConfiguration}).
 *
 * Derived and inspired by {@link org.springframework.data.auditing.config.AuditingBeanDefinitionRegistrarSupport}
 *
 * @author Steven Zgaljic
 */
public abstract class AclSecuredBeanDefinitionRegistrarSupport implements ImportBeanDefinitionRegistrar {

    private static final String ACL_SERVICE = "aclService";

    @Override
    public void registerBeanDefinitions(AnnotationMetadata annotationMetadata, BeanDefinitionRegistry registry) {
        Assert.notNull(annotationMetadata, "AnnotationMetadata must not be null!");
        Assert.notNull(annotationMetadata, "BeanDefinitionRegistry must not be null!");

        AbstractBeanDefinition ahbd = registerAclSecuredHandlerBeanDefinition(registry, getConfiguration(annotationMetadata));
        registerAclSecuredListenerBeanDefinition(ahbd, registry);
    }

    /**
     * Registers an appropriate BeanDefinition for an {@link AclSecuredHandler}.
     *
     * @param registry must not be {@literal null}.
     * @param configuration must not be {@literal null}.
     * @return
     */
    private AbstractBeanDefinition registerAclSecuredHandlerBeanDefinition(BeanDefinitionRegistry registry,
            AclSecuredConfiguration configuration) {

        Assert.notNull(registry, "BeanDefinitionRegistry must not be null!");
        Assert.notNull(configuration, "AclSecuredConfiguration must not be null!");

        AbstractBeanDefinition ahbd = getAclSecuredHandlerBeanDefinitionBuilder(configuration).getBeanDefinition();
        registry.registerBeanDefinition(getAclSecuredHandlerBeanName(), ahbd);
        return ahbd;
    }

    /**
     * Creates a {@link BeanDefinitionBuilder} to ease the definition of store specific {@link AclSecuredHandler}
     * implementations.
     *
     * @param configuration must not be {@literal null}.
     * @return
     */
    protected BeanDefinitionBuilder getAclSecuredHandlerBeanDefinitionBuilder(AclSecuredConfiguration configuration) {

        Assert.notNull(configuration, "AclSecuredConfiguration must not be null!");

        return configureDefaultAclSecuredHandlerAttributes(configuration,
                BeanDefinitionBuilder.rootBeanDefinition(DefaultAclSecuredHandler.class)); // TODO inject this?
    }

    /**
     * Configures the given {@link BeanDefinitionBuilder} with the default attributes from the given
     * {@link AclSecuredConfiguration}.
     *
     * @param configuration must not be {@literal null}.
     * @param builder must not be {@literal null}.
     * @return the builder with the acl secured attributes configured.
     */
    protected BeanDefinitionBuilder configureDefaultAclSecuredHandlerAttributes(AclSecuredConfiguration configuration,
                                                                                BeanDefinitionBuilder builder) {
        builder.addPropertyReference(ACL_SERVICE, configuration.getAclServiceRef());

        builder.setRole(AbstractBeanDefinition.ROLE_INFRASTRUCTURE);

        return builder;
    }

    /**
     * Retrieve acl secured configuration from the given {@link AnnotationMetadata}.
     *
     * @param annotationMetadata will never be {@literal null}.
     * @return
     */
    protected AclSecuredConfiguration getConfiguration(AnnotationMetadata annotationMetadata) {
        return new AnnotationAclSecuredConfiguration(annotationMetadata, getAnnotation());
    }

    /**
     * Return the first type to lookup configuration values from.
     *
     * @return must not be {@literal null}.
     */
    protected abstract Class<? extends Annotation> getAnnotation();

    /**
     * Register the listener to eventually trigger the {@link AclSecuredHandler}.
     *
     * @param aclSecuredHandlerDefinition will never be {@literal null}.
     * @param registry will never be {@literal null}.
     */
    protected abstract void registerAclSecuredListenerBeanDefinition(BeanDefinition aclSecuredHandlerDefinition,
        BeanDefinitionRegistry registry);

    /**
     * Return the name to be used to register the {@link AclSecuredHandler} under.
     *
     * @return
     */
    protected abstract String getAclSecuredHandlerBeanName();

    /**
     * Registers the given {@link AbstractBeanDefinition} as infrastructure bean under the given id.
     *
     * @param definition must not be {@literal null}.
     * @param id must not be {@literal null} or empty.
     * @param registry must not be {@literal null}.
     */
    protected void registerInfrastructureBeanWithId(AbstractBeanDefinition definition, String id,
                                                    BeanDefinitionRegistry registry) {
        definition.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        registry.registerBeanDefinition(id, definition);
    }

}
