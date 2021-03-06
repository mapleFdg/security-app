package com.maple.security.server;

import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import org.apache.commons.lang.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.builders.JdbcClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import com.maple.security.core.properties.OAuth2ClientProperties;
import com.maple.security.core.properties.SecurityProperties;

/**
 * 认证服务器配置
 * 
 * @author hzc
 *
 */
@Configuration
@EnableAuthorizationServer
public class MapleAuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private SecurityProperties securityProperties;

	@Autowired
	private TokenStore tokenStore;

	@Autowired(required = false)
	private JwtAccessTokenConverter jwtAccessTokenConverter;

	@Autowired(required = false)
	private TokenEnhancer jwtTokenEnhancer;
	
	@Autowired
	private DataSource dataSource;

	/**
	 * 认证及token配置
	 */
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager).userDetailsService(userDetailsService)
				.tokenStore(tokenStore);
		if (jwtAccessTokenConverter != null && jwtTokenEnhancer != null) {
			TokenEnhancerChain chain = new TokenEnhancerChain();
			List<TokenEnhancer> enhancers = new ArrayList<>();
			enhancers.add(jwtTokenEnhancer);
			enhancers.add(jwtAccessTokenConverter);
			chain.setTokenEnhancers(enhancers);

			endpoints.tokenEnhancer(chain).accessTokenConverter(jwtAccessTokenConverter);
		}
	}
	
	/**
	 * tokenkey的访问权限表达式配置,默认为denyAll()
	 */
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.tokenKeyAccess("permitAll()");
	}

	/**
	 * 客户端的配置
	 */
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

		InMemoryClientDetailsServiceBuilder builder = clients.inMemory();

		OAuth2ClientProperties[] configs = securityProperties.getOauth2().getClients();

		if (!ArrayUtils.isEmpty(configs)) {
			for (OAuth2ClientProperties config : configs) {
				builder.withClient(config.getClientId()).secret(config.getClientSecret())
						.accessTokenValiditySeconds(config.getAccessTokenValiditySeconds())
						.authorizedGrantTypes("refresh_token", "password").scopes("all", "write", "read");

			}
		}
	}

}
