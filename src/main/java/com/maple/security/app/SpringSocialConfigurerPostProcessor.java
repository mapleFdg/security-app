package com.maple.security.app;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

import com.maple.security.core.social.MapleSpringSocialConfigurer;

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
	 */
	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		if(StringUtils.equals(beanName, "mapleSocialSecurityConfig")) {
			MapleSpringSocialConfigurer configurer = (MapleSpringSocialConfigurer)bean;
			configurer.signupUrl("/social/signUp");
			return configurer;
		}
		return bean;
	}

}
