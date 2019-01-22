package com.jahnelgroup.springframework.security.acl.annotations.util;

import com.jahnelgroup.springframework.security.acl.annotations.AclRuntimeException;
import org.springframework.util.ReflectionUtils;

import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Useful functions to help with reflection.
 *
 * @author Steven Zgaljic
 */
public class ReflectionHelper {

    public static List<Field> getAllFields(List<Field> fields, Class<?> type) {
        fields.addAll(Arrays.asList(type.getDeclaredFields()));

        if (type.getSuperclass() != null) {
            getAllFields(fields, type.getSuperclass());
        }

        return fields;
    }

    public static List<Class> getClassHierarchy(List<Class> hierarchy, Class<?> type) {
        hierarchy.add(type);

        if (type.getSuperclass() != null) {
            getClassHierarchy(hierarchy, type.getSuperclass());
        }

        return hierarchy;
    }

    public static BiConsumer<Object, Field> IsSerializableConsumer(){
        return (object, field) -> {
            try{
                if ( ! (field.get(object) instanceof Serializable) ) {
                    throw new RuntimeException(String.format("Field %s for class %s must be Serializable",
                            field.getName(), object.getClass()));
                }
            }catch(Exception e){
                throw new AclRuntimeException(e);
            }
        };
    }

    public static <T extends Annotation> Triple<Object, Field, T> findAnnotatedField(Object object, Class<T> annotationClass) {
        return findAnnotatedField(object, annotationClass, null);
    }

    public static <T extends Annotation> Triple<Object, Field, T> findAnnotatedField(Object object, Class<T> annotationClass, BiConsumer<Object, Field> check) {
        List<Field> fields = ReflectionHelper.getAllFields(new LinkedList<>(), object.getClass());
        if (!fields.isEmpty()) {
            for (Field field : fields) {
                T annotation = field.getAnnotation(annotationClass);
                if (annotation != null) {
                    ReflectionUtils.makeAccessible(field);
                    if( check != null )
                        check.accept(object, field);
                    return new Triple<>(object, field, annotation);
                }
            }
        }
        return null;
    }

    public static <T extends Annotation> List<Triple<Object, Field, T>> findAllAnnotatedFields(Object object, Class<T> annotationClass) {
        return findAllAnnotatedFields(object, annotationClass, null);
    }

    public static <T extends Annotation> List<Triple<Object, Field, T>> findAllAnnotatedFields(Object object, Class<T> annotationClass, BiConsumer<Object, Field> check) {
        List<Triple<Object, Field, T>> results = new LinkedList<>();
        List<Field> fields = ReflectionHelper.getAllFields(new LinkedList<>(), object.getClass());
        if (!fields.isEmpty()) {
            for (Field field : fields) {
                T annotation = field.getAnnotation(annotationClass);
                if (annotation != null) {
                    ReflectionUtils.makeAccessible(field);
                    if( check != null )
                        check.accept(object, field);
                    results.add(new Triple<>(object, field, annotation));
                }
            }
        }
        return results;
    }

    public static <T extends Annotation> List<Tuple<Class, T>> findAnnotatedClasses(Object object, Class<T> annotationClass) {
        List<Tuple<Class, T>> results = new LinkedList<>();
        List<Class> classes = ReflectionHelper.getClassHierarchy(new LinkedList<>(), object.getClass());
        if (!classes.isEmpty()) {
            for (Class clazz : classes) {
                Annotation annotation = clazz.getAnnotation(annotationClass);
                if( annotation != null ){
                    results.add(new Tuple<>(clazz, (T)annotation));
                }

            }
        }
        return results;
    }

}
