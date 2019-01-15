package com.jahnelgroup.springframework.security.acl.annotations.util;

public class Triple<X, Y, Z> {
    public final X first;
    public final Y second;
    public final Z third;
    public Triple(X first, Y second, Z third) {
        this.first = first;
        this.second = second;
        this.third = third;
    }
}
