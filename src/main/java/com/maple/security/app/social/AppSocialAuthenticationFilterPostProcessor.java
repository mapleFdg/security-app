package com.maple.security.app.social;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.social.security.SocialAuthenticationFilter;
import org.springframework.stereotype.Component;

import com.maple.security.core.social.SocialAuthenticationFilterPostProcessor;

@Component
public class AppSocialAuthenticationFilterPostProcessor implements SocialAuthenticationFilterPostProcessor {

	@Autowired
	private AuthenticationSuccessHandler mapleAuthenticationSuccessHandler;
	
	@Override
	public void process(SocialAuthenticationFilter filter) {
		filter.setAuthenticationSuccessHandler(mapleAuthenticationSuccessHandler);
	}

}
