package com.plapp.authorization;


import org.springframework.security.core.GrantedAuthority;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;


public class ResourceAuthority implements GrantedAuthority, Serializable {
    private Long authorityId;

    private String authority;

    private List<Long> values = new ArrayList<>();

    private Long userId;

    public ResourceAuthority() {
        super();
    }

    public ResourceAuthority(String authority, Long userId) {
        super();
        this.authority = authority;
        this.userId = userId;
    }

    public void addValue(Long value) {
        values.add(value);
    }

    public Long getAuthorityId() {
        return authorityId;
    }

    public void setAuthorityId(Long authorityId) {
        this.authorityId = authorityId;
    }

    @Override
    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    public List<Long> getValues() {
        return values;
    }

    public void setValues(List<Long> values) {
        this.values = values;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    @Override
    public String toString() {
        return "ResourceAuthority{" +
                "authorityId=" + authorityId +
                ", authority='" + authority + '\'' +
                ", values=" + values +
                ", userId=" + userId +
                '}';
    }
}

