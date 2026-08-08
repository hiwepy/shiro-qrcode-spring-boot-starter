package org.apache.shiro.spring.boot.qrcode.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.qrcode.token.QrcodeAuthenticationToken;

/**
 * Qrcode AuthorizingRealm
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class QrcodeAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return QrcodeAuthenticationToken.class;
	}

}
