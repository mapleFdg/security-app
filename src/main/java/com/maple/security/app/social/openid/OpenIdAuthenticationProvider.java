package com.maple.security.app.social.openid;

import java.util.HashSet;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.social.security.SocialUserDetailsService;

public class OpenIdAuthenticationProvider implements AuthenticationProvider{
	
	private SocialUserDetailsService socialUserDetailsService;
	
	private UsersConnectionRepository usersConnectionRepository;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		OpenIdAuthenticationToken authenticationToken = (OpenIdAuthenticationToken)authentication;
		
		String openid = (String) authenticationToken.getPrincipal();
		
		String providerId = (String) authenticationToken.getCredentials();
		
		Set<String> openIds = new HashSet<>();
		openIds.add(openid);
		
		Set<String> userIds = getUsersConnectionRepository().findUserIdsConnectedTo(providerId, openIds);
		
		if(CollectionUtils.isEmpty(userIds) || userIds.size() != 1) {
			throw new InternalAuthenticationServiceException("无法获取用户信息");
		}
		
		String userId = userIds.iterator().next();
		
		UserDetails userDetails =getSocialUserDetailsService().loadUserByUserId(userId);
		
		OpenIdAuthenticationToken authenticationTokenResult = new OpenIdAuthenticationToken(userDetails,userDetails.getAuthorities());
		
		authenticationTokenResult.setDetails(authenticationToken.getDetails());
		
		return authenticationTokenResult;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OpenIdAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public SocialUserDetailsService getSocialUserDetailsService() {
		return socialUserDetailsService;
	}

	public void setSocialUserDetailsService(SocialUserDetailsService socialUserDetailsService) {
		this.socialUserDetailsService = socialUserDetailsService;
	}

	public UsersConnectionRepository getUsersConnectionRepository() {
		return usersConnectionRepository;
	}

	public void setUsersConnectionRepository(UsersConnectionRepository usersConnectionRepository) {
		this.usersConnectionRepository = usersConnectionRepository;
	}

}
