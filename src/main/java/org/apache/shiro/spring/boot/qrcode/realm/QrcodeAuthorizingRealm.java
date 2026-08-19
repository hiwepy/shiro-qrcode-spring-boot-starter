package org.apache.shiro.spring.boot.qrcode.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.qrcode.token.QrcodeAuthenticationToken;

/**
 * Qrcode AuthorizingRealm
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class QrcodeAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	/**
	 * Returns the authentication token class.
	 *
	 * @return the authentication token class
	 */
	public Class<?> getAuthenticationTokenClass() {
		return QrcodeAuthenticationToken.class;
	}

}
