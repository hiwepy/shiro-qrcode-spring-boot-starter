package org.apache.shiro.spring.boot.qrcode.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.qrcode.token.QrcodeAuthenticationToken;

/**
 * Qrcode AuthorizingRealm
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class QrcodeAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return QrcodeAuthenticationToken.class;
	}

}
