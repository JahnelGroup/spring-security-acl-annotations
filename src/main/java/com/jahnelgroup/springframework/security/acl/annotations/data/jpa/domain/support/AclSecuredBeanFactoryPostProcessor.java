package com.jahnelgroup.springframework.security.acl.annotations.data.jpa.domain.support;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.aspectj.AnnotationBeanConfigurerAspect;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;

import static org.springframework.data.jpa.util.BeanDefinitionUtils.getBeanDefinition;
import static org.springframework.data.jpa.util.BeanDefinitionUtils.getEntityManagerFactoryBeanNames;
import static org.springframework.util.StringUtils.addStringToArray;

/**
 * {@link BeanFactoryPostProcessor} that ensures that the {@link AnnotationBeanConfigurerAspect} aspect is up and
 * running <em>before</em> the {@link javax.persistence.EntityManagerFactory} gets created as this already instantiates
 * entity listeners and we need to get injection into {@link org.springframework.beans.factory.annotation.Configurable}
 * to work in them.
 *
 * Derived and inspired by {@link org.springframework.data.jpa.domain.support.AuditingBeanFactoryPostProcessor}
 *
 * @author Steven Zgaljic
 */
public class AclSecuredBeanFactoryPostProcessor implements BeanFactoryPostProcessor {

    public static final String BEAN_CONFIGURER_ASPECT_BEAN_NAME = "org.springframework.context.config.internalBeanConfigurerAspect";

    public AclSecuredBeanFactoryPostProcessor() {
    }

    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
        try {
            getBeanDefinition(BEAN_CONFIGURER_ASPECT_BEAN_NAME, beanFactory);
        } catch (NoSuchBeanDefinitionException o_O) {
            throw new IllegalStateException(
                    "Invalid auditing setup! Make sure you've used @EnableJpaAuditing correctly!", o_O);
        }

        for (String beanName : getEntityManagerFactoryBeanNames(beanFactory)) {
            BeanDefinition definition = getBeanDefinition(beanName, beanFactory);
            definition.setDependsOn(addStringToArray(definition.getDependsOn(), BEAN_CONFIGURER_ASPECT_BEAN_NAME));
        }

    }
}
