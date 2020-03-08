package com.maple.security.app.authentication.openid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.social.security.SocialUserDetailsService;
import org.springframework.stereotype.Component;

/**
 * 
 * openid登录相关的Config配置
 * 
 * @author hzc
 *
 */
@Component
public class OpenIdAuthenticationSecurityConfig
		extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	@Autowired
	private SocialUserDetailsService socialUserDetailsService;

	@Autowired
	private UsersConnectionRepository usersConnectionRepository;

	@Autowired
	private AuthenticationSuccessHandler mapleAuthenticationSuccessHandler;

	@Autowired
	private AuthenticationFailureHandler mapleAuthenticationFailureHandler;

	@Override
	public void configure(HttpSecurity http) throws Exception {

		OpenIdAuthenticationFilter filter = new OpenIdAuthenticationFilter();
		filter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
		filter.setAuthenticationSuccessHandler(mapleAuthenticationSuccessHandler);
		filter.setAuthenticationFailureHandler(mapleAuthenticationFailureHandler);

		OpenIdAuthenticationProvider provider = new OpenIdAuthenticationProvider();
		provider.setSocialUserDetailsService(socialUserDetailsService);
		provider.setUsersConnectionRepository(usersConnectionRepository);

		http.authenticationProvider(provider).addFilterAfter(filter, UsernamePasswordAuthenticationFilter.class);

	}

}
