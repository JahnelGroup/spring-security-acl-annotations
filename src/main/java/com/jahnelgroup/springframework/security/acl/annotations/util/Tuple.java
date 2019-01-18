package com.jahnelgroup.springframework.security.acl.annotations.util;

/**
 * Represents a grouping of two generic elements.
 * @param <X>
 * @param <Y>
 * @author Steven Zgaljic
 */
public class Tuple<X, Y> {
    public final X first;
    public final Y second;
    public Tuple(X first, Y second) {
        this.first = first;
        this.second = second;
    }
}
