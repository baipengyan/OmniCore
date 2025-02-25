package com.beloved.omnicoreauthorizationserver.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.beloved.omnicoreauthorizationserver.beanmapper.UsersBeanMapper;
import com.beloved.omnicoreauthorizationserver.domain.Authorities;
import com.beloved.omnicoreauthorizationserver.domain.Users;
import com.beloved.omnicoreauthorizationserver.mapper.AuthoritiesMapper;
import com.beloved.omnicoreauthorizationserver.mapper.UsersMapper;
import com.beloved.omnicoreauthorizationserver.service.impl.ChickUserDetails;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author baipengyan
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UsersMapper usersMapper;
    private final AuthoritiesMapper authoritiesMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Assert.hasText(username, "用户名不能为空");
        // 查询用户信息
        Users users = usersMapper.selectById(username);
        if (ObjectUtils.isEmpty(users)) {
            throw new UsernameNotFoundException(username + " not found");
        }
        // 转换
        ChickUserDetails chickUserDetails = UsersBeanMapper.INSTANCE.usersToUserDetails(users);

        // 查询用户权限
        LambdaQueryWrapper<Authorities> authoritiesLambdaQueryWrapper = new LambdaQueryWrapper<>();
        authoritiesLambdaQueryWrapper.eq(Authorities::getUsername, username);
        List<Authorities> authorities = authoritiesMapper.selectList(authoritiesLambdaQueryWrapper);

        Set<GrantedAuthority> simpleGrantedAuthorities = new HashSet<>();
        if (CollectionUtils.isNotEmpty(authorities)) {
            authorities.forEach(authority -> {
                SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(authority.getAuthority());
                simpleGrantedAuthorities.add(simpleGrantedAuthority);
            });
        }
        chickUserDetails.setAuthorities(simpleGrantedAuthorities);
        return chickUserDetails;
    }
}

