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

package com.alibaba.nacos.client.auth;
import java.util.Properties;

/**
 * Client AuthService.
 *
 * @author wuyfee
 */
public interface ClientAuthService {
    
    /**
     * login(request) to service and get response.
     * @param properties login information.
     * @return boolean whether login success.
     */
    boolean login(Properties properties);
    
    /**
     * ClientAuthService Name which for conveniently find ClientAuthService instance.
     * @return ClientAuthServiceName mark clientAuthService.
     */
    String getClientAuthServiceName();
    
    /**
     * package request and execute request.
     * @param properties login information.
     * @return Object request result.
     */
    boolean restRequest(Properties properties);
    
}
