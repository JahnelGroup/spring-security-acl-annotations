package com.jahnelgroup.springframework.security.acl.annotations;

public class AclRuntimeException extends RuntimeException {

    private String message;

    public AclRuntimeException(Exception e) {
        super(e);
    }

    public AclRuntimeException(String message) {
        super(message);
    }

    public AclRuntimeException(String message, Exception e) {
        super(message, e);
    }
}
