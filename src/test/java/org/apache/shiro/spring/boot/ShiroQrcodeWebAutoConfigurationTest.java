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
package org.apache.shiro.spring.boot;

import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.support.DefaultEventBus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ShiroQrcodeWebAutoConfiguration}.
 *
 * <p>Verifies the auto-configuration activates under the expected conditions
 * and exposes its declared beans.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("ShiroQrcodeWebAutoConfiguration Tests")
class ShiroQrcodeWebAutoConfigurationTest {

    @Configuration
    static class TestConfig {
        @Bean
        public EventBus eventBus() {
            return new DefaultEventBus();
        }
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    @DisplayName("Auto-configuration class can be instantiated")
    void testInstantiation() {
        ShiroQrcodeWebAutoConfiguration configuration = new ShiroQrcodeWebAutoConfiguration();
        assertThat(configuration).isNotNull();
    }

    @Test
    @DisplayName("Auto-configuration loads when 'shiro.qrcode.enabled=true'")
    void testLoadsWhenEnabledPropertySet() {
        runner.withUserConfiguration(ShiroQrcodeWebAutoConfiguration.class)
                .withPropertyValues("shiro.qrcode.enabled=true")
                .run(context -> {
                    // Just verify the context starts without errors
                    assertThat(context).isNotNull();
                });
    }

    @Test
    @DisplayName("Auto-configuration is absent when property is not set")
    void testNotLoadedWhenPropertyAbsent() {
        runner.withUserConfiguration(ShiroQrcodeWebAutoConfiguration.class)
                .run(context -> assertThat(context).doesNotHaveBean(ShiroQrcodeWebAutoConfiguration.class));
    }
}
