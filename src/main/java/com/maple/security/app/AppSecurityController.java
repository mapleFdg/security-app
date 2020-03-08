package com.maple.security.app;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.web.ProviderSignInUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import com.maple.security.app.social.AppSignUpUtil;
import com.maple.security.core.properties.SecurityConstants;
import com.maple.security.core.social.SocialController;
import com.maple.security.core.social.SocialUserInfo;

/**
 * APP 系统定义处理的url
 * 
 * @author hzc
 *
 */
@RestController
public class AppSecurityController extends SocialController {

	@Autowired
	private ProviderSignInUtils providerSignInUtils;

	@Autowired
	private AppSignUpUtil appSignUpUtil;

	/**
	 * 需要注册时跳到这里，返回401和用户信息给前端
	 * 
	 * @param request
	 * @return
	 */
	@GetMapping(SecurityConstants.DEFAULT_SOCIAL_USER_INFO_URL)
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	public SocialUserInfo getSocialUserInfo(HttpServletRequest request) {
		
		Connection<?> connectionFromSession = providerSignInUtils
				.getConnectionFromSession(new ServletWebRequest(request));

		appSignUpUtil.saveConnectionData(new ServletWebRequest(request), connectionFromSession.createData());

		return buildSocialUserInfo(connectionFromSession);
	}

}
