package com.maple.security.app.validate.code.impl;

import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;

import com.maple.security.core.validate.code.ValidateCode;
import com.maple.security.core.validate.code.ValidateCodeException;
import com.maple.security.core.validate.code.ValidateCodeRepository;
import com.maple.security.core.validate.code.ValidateCodeType;

@Component
public class RedisValidateCodeRepository implements ValidateCodeRepository{

	@Autowired
	private RedisTemplate<Object, Object> redisTemplate;
	
	@Override
	public void save(ServletWebRequest request, ValidateCode validateCode, ValidateCodeType validateCodeType) {
		redisTemplate.opsForValue().set(buildKey(request, validateCodeType), validateCode,30,TimeUnit.MINUTES);
	}

	@Override
	public ValidateCode get(ServletWebRequest request, ValidateCodeType validateCodeType) {
		Object object = redisTemplate.opsForValue().get(buildKey(request, validateCodeType));
		
		if(object == null) {
			return null;
		}
		return (ValidateCode)object;
	}

	@Override
	public void remove(ServletWebRequest request, ValidateCodeType validateCodeType) {
		redisTemplate.delete(buildKey(request, validateCodeType));
	
	}
	
	
	private String buildKey(ServletWebRequest request, ValidateCodeType validateCodeType) {
		String deviceId = request.getHeader("deviceId");
		
		if(StringUtils.isBlank(deviceId)) {
			throw new ValidateCodeException("请在请求头中携带deviceId参数");
		}
		return "code:" + validateCodeType.toString().toLowerCase() + ":" + deviceId;
	}

}
