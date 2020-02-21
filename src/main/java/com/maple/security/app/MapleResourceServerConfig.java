package com.maple.security.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.social.security.SpringSocialConfigurer;

import com.maple.security.app.social.openid.OpenIdAuthenticationSecurityConfig;
import com.maple.security.core.authentication.mobile.SmsAuthenticationSecurityConfig;
import com.maple.security.core.properties.SecurityConstants;
import com.maple.security.core.properties.SecurityProperties;
import com.maple.security.core.validate.code.ValidateCodeSecurityConfig;

@Configuration
@EnableResourceServer
public class MapleResourceServerConfig extends ResourceServerConfigurerAdapter {

	/**
	 * 系统配置
	 */
	@Autowired
	private SecurityProperties securityProperties;
	
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

	/**
	 * 第三方登录配置类
	 */
	@Autowired
	private SpringSocialConfigurer mapleSocialSecurityConfig;

	@Override
	public void configure(HttpSecurity http) throws Exception {

		http.formLogin().loginPage(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL) // 自定义登录页面
				.loginProcessingUrl(SecurityConstants.DEFAULT_SIGN_IN_PROCESSING_URL_FORM) // 配置登录的处理页面
				.successHandler(mapleAuthenticationSuccessHandler) // 自定义登录成功处理
				.failureHandler(mapleAuthenticationFailureHandler); // 自定义登录失败处理

		http.apply(validateCodeSecurityConfig) // 加载校验码配置信息
			.and()
				.apply(smsAuthenticationSecurityConfig)  // 加载短信登录的的配置
			.and()
				.apply(mapleSocialSecurityConfig) // 加载第三方登录的配置
			.and()
				.apply(openIdAuthenticationSecurityConfig) // 加载关于openid的登录方式
			.and()
				.authorizeRequests() // 配置拦截的请求
				.antMatchers(securityProperties.getBrowser().getLoginPage(),
						SecurityConstants.DEFAULT_UNAUTHENTICATION_URL,
						SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX + "/*",
						securityProperties.getBrowser().getSignUpUrl(),
						SecurityConstants.DEFAULT_SIGN_IN_PROCESSING_URL_OPENID,
						"/hello",
						"/social/signUp",
						"/social/regist",
						securityProperties.getBrowser().getSession().getSessionInvalidUrl()) // 排除掉哪些请求
				.permitAll()
				.anyRequest()
				.authenticated()
			.and()
				.csrf() // csrf防护
				.disable();
	}

}
