package com.maple.security.app.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.maple.security.core.support.SimpleResponse;

/**
 * APP环境下认证失败处理器
 * 
 * @author hzc
 *
 */
@Component("mapleAuthenticationFailureHandler")
public class MapleAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

	private Logger log = LoggerFactory.getLogger(MapleAuthenticationSuccessHandler.class);

	@Autowired
	private ObjectMapper objectMapper;

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		log.info("登录失败，失败信息：" + exception.getMessage());

		response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
		response.setContentType("application/json;charset=UTF-8");
		response.getWriter().write(objectMapper.writeValueAsString(new SimpleResponse(exception.getMessage())));
	}

}
