package org.apache.shiro.spring.boot.qrcode.token;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link QrcodeAuthenticationToken}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("QrcodeAuthenticationToken Tests")
class QrcodeAuthenticationTokenTest {

    @Test
    @DisplayName("Token can be instantiated")
    void testInstantiation() {
        QrcodeAuthenticationToken token = new QrcodeAuthenticationToken();
        assertThat(token).isNotNull();
    }

    @Test
    @DisplayName("UUID getter and setter work correctly")
    void testUuidGetterSetter() {
        QrcodeAuthenticationToken token = new QrcodeAuthenticationToken();
        token.setUuid("test-uuid-123");
        assertThat(token.getUuid()).isEqualTo("test-uuid-123");
    }

    @Test
    @DisplayName("Default UUID is null")
    void testDefaultUuid() {
        QrcodeAuthenticationToken token = new QrcodeAuthenticationToken();
        assertThat(token.getUuid()).isNull();
    }

    @Test
    @DisplayName("UUID can be set to null")
    void testUuidNull() {
        QrcodeAuthenticationToken token = new QrcodeAuthenticationToken();
        token.setUuid("test");
        token.setUuid(null);
        assertThat(token.getUuid()).isNull();
    }

    @Test
    @DisplayName("Extends DefaultAuthenticationToken")
    void testExtendsDefaultAuthenticationToken() {
        QrcodeAuthenticationToken token = new QrcodeAuthenticationToken();
        assertThat(token).isInstanceOf(org.apache.shiro.biz.authc.token.DefaultAuthenticationToken.class);
    }
}
