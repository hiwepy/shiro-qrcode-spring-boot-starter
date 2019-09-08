package org.apache.shiro.spring.boot.qrcode.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.qrcode.token.QrcodeLoginToken;

/**
 * Qrcode AuthorizingRealm
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class QrcodeAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return QrcodeLoginToken.class;// 此Realm只支持QrcodeLoginToken
	}

}
