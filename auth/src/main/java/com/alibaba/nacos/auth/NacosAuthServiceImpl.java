/*
 * Copyright 1999-2021 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.auth;

import com.alibaba.nacos.api.common.Constants;
import com.alibaba.nacos.auth.context.IdentityContext;
import com.alibaba.nacos.auth.exception.AccessException;
import com.alibaba.nacos.auth.model.NacosUser;
import com.alibaba.nacos.auth.model.Permission;
import com.alibaba.nacos.auth.roles.NacosRoleServiceImpl;
import com.alibaba.nacos.auth.roles.RoleInfo;
import com.alibaba.nacos.auth.util.Loggers;
import com.alibaba.nacos.common.utils.StringUtils;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

/**
 * Builtin access control entry of Nacos.
 *
 * @author wuyfee
 */
public class NacosAuthServiceImpl implements AuthService {
    
    private static final String TOKEN_PREFIX = "Bearer ";
    
    private static final String PARAM_USERNAME = "username";
    
    private static final String PARAM_PASSWORD = "password";
    
    @Autowired
    private JwtTokenManager tokenManager;
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private NacosRoleServiceImpl roleService;
    
    @Override
    public Boolean login(IdentityContext identityContext) throws AccessException {
        String token = resolveToken(identityContext);
        if (StringUtils.isBlank(token)) {
            throw new AccessException("user not found!");
        }
        
        try {
            tokenManager.validateToken(token);
        } catch (ExpiredJwtException e) {
            throw new AccessException("token expired!");
        } catch (Exception e) {
            throw new AccessException("token invalid!");
        }
        
        Authentication authentication = tokenManager.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        String username = authentication.getName();
        NacosUser user = new NacosUser();
        user.setUserName(username);
        user.setToken(token);
        List<RoleInfo> roleInfoList = roleService.getRoles(username);
        if (roleInfoList != null) {
            for (RoleInfo roleInfo : roleInfoList) {
                if (roleInfo.getRole().equals(NacosRoleServiceImpl.GLOBAL_ADMIN_ROLE)) {
                    user.setGlobalAdmin(true);
                    break;
                }
            }
        }
        return true;
    }
    
    @Override
    public Boolean authorityAccess(IdentityContext identityContext, Permission permission) throws AccessException {
        
        if (Loggers.AUTH.isDebugEnabled()) {
            Loggers.AUTH.debug("auth permission: {}, user: {}", permission,
                    (String) identityContext.getParameter(PARAM_USERNAME));
        }
        
        if (!roleService.hasPermission((String) identityContext.getParameter(PARAM_USERNAME), permission)) {
            throw new AccessException("authorization failed!");
        }
        return true;
    }
    
    @Override
    public String getAuthServiceName() {
        return null;
    }
    
    /**
     * Get token from header.
     */
    private String resolveToken(IdentityContext identityContext) throws AccessException {
        String bearerToken = (String) identityContext.getParameter(NacosAuthConfig.AUTHORIZATION_HEADER);
        if (StringUtils.isNotBlank(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(7);
        }
        bearerToken = (String) identityContext.getParameter(Constants.ACCESS_TOKEN);
        if (StringUtils.isBlank(bearerToken)) {
            String userName = (String) identityContext.getParameter(PARAM_USERNAME);
            String password = (String) identityContext.getParameter(PARAM_PASSWORD);
            bearerToken = resolveTokenFromUser(userName, password);
        }
        
        return bearerToken;
    }
    
    private String resolveTokenFromUser(String userName, String rawPassword) throws AccessException {
        String finalName;
        Authentication authenticate;
        try {
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userName,
                    rawPassword);
            authenticate = authenticationManager.authenticate(authenticationToken);
        } catch (AuthenticationException e) {
            throw new AccessException("unknown user!");
        }
        
        if (null == authenticate || StringUtils.isBlank(authenticate.getName())) {
            finalName = userName;
        } else {
            finalName = authenticate.getName();
        }
        
        return tokenManager.createToken(finalName);
    }
}
