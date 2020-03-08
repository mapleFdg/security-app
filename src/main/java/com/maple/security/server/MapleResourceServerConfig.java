package com.maple.security.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.social.security.SpringSocialConfigurer;

import com.maple.security.app.authentication.openid.OpenIdAuthenticationSecurityConfig;
import com.maple.security.core.authentication.FormAuthenticationConfig;
import com.maple.security.core.authentication.mobile.SmsAuthenticationSecurityConfig;
import com.maple.security.core.authorize.AuthorizeConfigManager;
import com.maple.security.core.validate.code.ValidateCodeSecurityConfig;

/**
 * 资源服务器配置
 * 
 * @author hzc
 *
 */
@Configuration
@EnableResourceServer
public class MapleResourceServerConfig extends ResourceServerConfigurerAdapter {

	@Autowired
	private ValidateCodeSecurityConfig validateCodeSecurityConfig;

	@Autowired
	private OpenIdAuthenticationSecurityConfig openIdAuthenticationSecurityConfig;

	@Autowired
	private SmsAuthenticationSecurityConfig smsAuthenticationSecurityConfig;

	@Autowired
	protected AuthenticationSuccessHandler mapleAuthenticationSuccessHandler;

	@Autowired
	protected AuthenticationFailureHandler mapleAuthenticationFailureHandler;
	
	@Autowired
	private FormAuthenticationConfig formAuthenticationConfig;

	/**
	 * 第三方登录配置类
	 */
	@Autowired
	private SpringSocialConfigurer mapleSocialSecurityConfig;

	@Autowired
	private AuthorizeConfigManager authorizeConfigManager;

	@Override
	public void configure(HttpSecurity http) throws Exception {

		// 表单登录配置
		formAuthenticationConfig.configure(http);

		http.apply(validateCodeSecurityConfig) // 加载校验码配置信息
				.and()
			.apply(smsAuthenticationSecurityConfig) // 加载短信登录的的配置
				.and()
			.apply(mapleSocialSecurityConfig) // 加载第三方登录的配置
				.and()
			.apply(openIdAuthenticationSecurityConfig) // 加载关于openid的登录方式
				.and()
			.csrf().disable();

		// 权限配置
		authorizeConfigManager.config(http.authorizeRequests());
	}

}
