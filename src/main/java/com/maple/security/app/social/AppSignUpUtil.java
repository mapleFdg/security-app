package com.maple.security.app.social;

import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.ConnectionData;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import com.maple.security.app.AppSecurityException;

@Component
public class AppSignUpUtil {

	@Autowired
	private RedisTemplate<Object, Object> redisTemplate;

	@Autowired
	private ConnectionFactoryLocator connectionFactoryLocator;
	
	@Autowired
	private UsersConnectionRepository usersConnectionRepository;

	/**
	 * 将connectData存进redis
	 * 
	 * @param request
	 * @param connectionData
	 */
	public void saveConnectionData(WebRequest request, ConnectionData connectionData) {
		redisTemplate.opsForValue().set(getKey(request), connectionData, 10, TimeUnit.MINUTES);
	}

	public void doPostSignUp(WebRequest request,String userId) {
		String key = getKey(request);
		if(!redisTemplate.hasKey(key)) {
			throw new AppSecurityException("无法找到缓存的用户社交账号信息");
		}
		
		ConnectionData connectionData = (ConnectionData) redisTemplate.opsForValue().get(key);
		
		Connection<?> connection = connectionFactoryLocator.getConnectionFactory(connectionData.getProviderId()).createConnection(connectionData);
		
		usersConnectionRepository.createConnectionRepository(userId).addConnection(connection);
		
		redisTemplate.delete(key);
	}

	/**
	 * 获取存进redis的KEY值
	 * 
	 * @param request
	 * @return
	 */
	private String getKey(WebRequest request) {
		String deviceId = request.getHeader("deviceId");
		if (StringUtils.isBlank(deviceId)) {
			throw new AppSecurityException("设备Id不能为空");
		}
		return "maple:security:social.connect." + deviceId;
	}

}
