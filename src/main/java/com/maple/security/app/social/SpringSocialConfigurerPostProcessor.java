package com.maple.security.app.social;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

import com.maple.security.core.properties.SecurityConstants;
import com.maple.security.core.social.support.MapleSpringSocialConfigurer;

/**
 * 
 * 在bean初始化前与初始化后做响应的处理
 * 
 * @author hzc
 *
 */
@Component
public class SpringSocialConfigurerPostProcessor implements BeanPostProcessor {

	/**
	 * bean 初始化前处理
	 */
	@Override
	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

	/**
	 * bean 初始化后处理
	 * 
	 * 修改APP的注册URL地址
	 * 
	 */
	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		if(StringUtils.equals(beanName, "mapleSocialSecurityConfig")) {
			MapleSpringSocialConfigurer configurer = (MapleSpringSocialConfigurer)bean;
			configurer.signupUrl(SecurityConstants.DEFAULT_SOCIAL_USER_INFO_URL);
			return configurer;
		}
		return bean;
	}

}
