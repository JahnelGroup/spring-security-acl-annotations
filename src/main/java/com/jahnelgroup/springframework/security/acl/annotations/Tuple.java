package com.jahnelgroup.springframework.security.acl.annotations;

class Tuple<X, Y> {
    public final X annotation;
    public final Y field;
    public Tuple(X annotation, Y field) {
        this.annotation = annotation;
        this.field = field;
    }
}
