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
package org.apache.shiro.spring.boot.qrcode;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link QrcodeInfo}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("QrcodeInfo Tests")
class QrcodeInfoTest {

    private static void setField(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    private static Object getField(Object obj, String fieldName) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        QrcodeInfo instance = new QrcodeInfo();
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("UUID field can be set and read via reflection")
    void testUuidField() throws Exception {
        QrcodeInfo info = new QrcodeInfo();
        setField(info, "uuid", "test-uuid-123");
        assertThat(getField(info, "uuid")).isEqualTo("test-uuid-123");
    }

    @Test
    @DisplayName("UserId field can be set and read via reflection")
    void testUserIdField() throws Exception {
        QrcodeInfo info = new QrcodeInfo();
        setField(info, "userId", "user-456");
        assertThat(getField(info, "userId")).isEqualTo("user-456");
    }

    @Test
    @DisplayName("Default values are null")
    void testDefaultValues() throws Exception {
        QrcodeInfo info = new QrcodeInfo();
        assertThat(getField(info, "uuid")).isNull();
        assertThat(getField(info, "userId")).isNull();
    }
}
