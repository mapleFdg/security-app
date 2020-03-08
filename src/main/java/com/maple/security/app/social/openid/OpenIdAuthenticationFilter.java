package com.maple.security.app.social.openid;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import com.maple.security.core.properties.SecurityConstants;

public class OpenIdAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
// ~ Static fields/initializers
// =====================================================================================

	public static final String SPRING_SECURITY_FORM_OPENID_KEY = "openId";
	public static final String SPRING_SECURITY_FORM_PROVIDERID_KEY = "providerId";

	private String openIdParameter = SPRING_SECURITY_FORM_OPENID_KEY;
	private String providerIdParameter = SPRING_SECURITY_FORM_PROVIDERID_KEY;
	private boolean postOnly = true;

// ~ Constructors
// ===================================================================================================

	public OpenIdAuthenticationFilter() {
		super(new AntPathRequestMatcher(SecurityConstants.DEFAULT_SIGN_IN_PROCESSING_URL_OPENID, "POST"));
	}

// ~ Methods
// ========================================================================================================

	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		if (postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}

		String openId = obtainOpenId(request);
		String providerId = obtainProviderId(request);

		if (openId == null) {
			throw new AuthenticationServiceException("openId不能为空");
		}

		if (providerId == null) {
			throw new AuthenticationServiceException("providerId不能为空");
		}

		OpenIdAuthenticationToken authRequest = new OpenIdAuthenticationToken(openId, providerId);

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		return this.getAuthenticationManager().authenticate(authRequest);
	}

	
	protected String obtainProviderId(HttpServletRequest request) {
		return request.getParameter(providerIdParameter);
	}

	
	protected String obtainOpenId(HttpServletRequest request) {
		return request.getParameter(openIdParameter);
	}

	/**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request     that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its
	 *                    details set
	 */
	protected void setDetails(HttpServletRequest request, OpenIdAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}

	/**
	 * Sets the parameter name which will be used to obtain the username from the
	 * login request.
	 *
	 * @param usernameParameter the parameter name. Defaults to "username".
	 */
	public void setOpenIdParameter(String openIdParameter) {
		Assert.hasText(openIdParameter, "openId parameter must not be empty or null");
		this.openIdParameter = openIdParameter;
	}

	/**
	 * Sets the parameter name which will be used to obtain the password from the
	 * login request..
	 *
	 * @param passwordParameter the parameter name. Defaults to "password".
	 */
	public void setProviderIdParameter(String providerIdParameter) {
		Assert.hasText(providerIdParameter, "Provider parameter must not be empty or null");
		this.providerIdParameter = providerIdParameter;
	}

	/**
	 * Defines whether only HTTP POST requests will be allowed by this filter. If
	 * set to true, and an authentication request is received which is not a POST
	 * request, an exception will be raised immediately and authentication will not
	 * be attempted. The <tt>unsuccessfulAuthentication()</tt> method will be called
	 * as if handling a failed authentication.
	 * <p>
	 * Defaults to <tt>true</tt> but may be overridden by subclasses.
	 */
	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

	public final String getOpenIdParameter() {
		return openIdParameter;
	}

	public final String getProviderIdParameter() {
		return providerIdParameter;
	}
}