package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
 * 로그인을 진행이 완료가 되면 시큐리티 session을 만들어준다. (Security ContextHolder)
 * 오브젝트 -> Authentication 타입 객체
 * Authentication 안에 User정보가 있어야 됨
 * User 오브젝트 타입 -> UserDetails 타입 객체
 *
 * Security Session -> Authentication -> UserDetails(PrincipalDetails)
 */

@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;
    private Map<String, Object> attribute;

    // 일반 로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    //OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attribute) {
        this.user = user;
        this.attribute = attribute;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attribute;
    }

    @Override
    public String getName() {
        return null;
    }

    // 해당 User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });

        return collection;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
