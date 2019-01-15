package com.jahnelgroup.springframework.security.acl.annotations.config;

import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.Assert;

import java.lang.annotation.Annotation;
import java.util.Map;

/**
 * Default implementation for {@link AclSecuredConfiguration}.
 *
 * Derived and inspired by {@link org.springframework.data.auditing.config.AnnotationAuditingConfiguration}
 *
 * @author Steven Zgaljic
 */
public class AnnotationAclSecuredConfiguration implements AclSecuredConfiguration {

    private static final String MISSING_ANNOTATION_ATTRIBUTES = "Couldn't find first attributes for %s in %s!";

    private final AnnotationAttributes attributes;

    public AnnotationAclSecuredConfiguration(AnnotationMetadata metadata, Class<? extends Annotation> annotation) {
        Assert.notNull(metadata, "AnnotationMetadata must not be null!");
        Assert.notNull(annotation, "Annotation must not be null!");

        Map<String, Object> attributesSource = metadata.getAnnotationAttributes(annotation.getName());

        if (attributesSource == null) {
            throw new IllegalArgumentException(String.format(MISSING_ANNOTATION_ATTRIBUTES, annotation, metadata));
        }

        this.attributes = new AnnotationAttributes(attributesSource);
    }

    @Override
    public String getAclSecuredHandlerRef() {
        return attributes.getString("aclSecuredHandlerRef");
    }

    @Override
    public String getAclServiceRef() {
        return attributes.getString("aclServiceRef");
    }
}
