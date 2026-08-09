/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.qrcode.endpoint;

import com.google.zxing.spring.boot.ZxingQrCodeTemplate;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link ShiroQrcodeEndpoint}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("ShiroQrcodeEndpoint Tests")
class ShiroQrcodeEndpointTest {

    @Test
    @DisplayName("Endpoint class can be instantiated with dependencies")
    void testInstantiation() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        ZxingQrCodeTemplate qrcodeTemplate = mock(ZxingQrCodeTemplate.class);
        ShiroQrcodeEndpoint endpoint = new ShiroQrcodeEndpoint(redisTemplate, qrcodeTemplate);
        assertThat(endpoint).isNotNull();
    }

    @Test
    @DisplayName("getStringRedisTemplate returns the injected template")
    void testGetRedisTemplate() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        ZxingQrCodeTemplate qrcodeTemplate = mock(ZxingQrCodeTemplate.class);
        ShiroQrcodeEndpoint endpoint = new ShiroQrcodeEndpoint(redisTemplate, qrcodeTemplate);
        assertThat(endpoint.getStringRedisTemplate()).isEqualTo(redisTemplate);
    }

    @Test
    @DisplayName("getQrcodeTemplate returns the injected template")
    void testGetQrcodeTemplate() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        ZxingQrCodeTemplate qrcodeTemplate = mock(ZxingQrCodeTemplate.class);
        ShiroQrcodeEndpoint endpoint = new ShiroQrcodeEndpoint(redisTemplate, qrcodeTemplate);
        assertThat(endpoint.getQrcodeTemplate()).isEqualTo(qrcodeTemplate);
    }
}
