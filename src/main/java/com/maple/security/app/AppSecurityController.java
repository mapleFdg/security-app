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
import com.maple.security.core.social.SocialUserInfo;

@RestController
public class AppSecurityController {
	
	@Autowired
	private ProviderSignInUtils providerSignInUtils;
	
	@Autowired
	private AppSignUpUtil appSignUpUtil;

	
	@GetMapping("/social/signUp")
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	public SocialUserInfo getSocialUserInfo(HttpServletRequest request) {
		SocialUserInfo socialUserInfo = new SocialUserInfo();
		
		Connection<?> connectionFromSession = providerSignInUtils.getConnectionFromSession(new ServletWebRequest(request));
		socialUserInfo.setProviderId(connectionFromSession.getKey().getProviderId());
		socialUserInfo.setProviderUserId(connectionFromSession.getKey().getProviderUserId());
		socialUserInfo.setNickName(connectionFromSession.getDisplayName());
		socialUserInfo.setHeadimg(connectionFromSession.getImageUrl());
		
		appSignUpUtil.saveConnectionData(new ServletWebRequest(request), connectionFromSession.createData());
		
		return socialUserInfo;
	} 
	
}
