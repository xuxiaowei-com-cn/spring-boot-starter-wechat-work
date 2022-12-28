package org.springframework.security.oauth2.server.authorization.client;

/*-
 * #%L
 * spring-boot-starter-wechat-work
 * %%
 * Copyright (C) 2022 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.WeChatWorkWebsiteAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2WeChatWorkParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.exception.AppidWeChatWorkException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectUriWeChatWorkException;
import org.springframework.security.oauth2.server.authorization.exception.RedirectWeChatWorkException;
import org.springframework.security.oauth2.server.authorization.properties.WeChatWorkWebsiteProperties;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2WeChatWorkWebsiteEndpointUtils;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * 企业微信 扫码授权登录 账户服务接口 基于内存的实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class InMemoryWeChatWorkWebsiteService implements WeChatWorkWebsiteService {

	private final WeChatWorkWebsiteProperties weChatWorkWebsiteProperties;

	public InMemoryWeChatWorkWebsiteService(WeChatWorkWebsiteProperties weChatWorkWebsiteProperties) {
		this.weChatWorkWebsiteProperties = weChatWorkWebsiteProperties;
	}

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 开放平台 网站应用 ID
	 * @param agentid 访问
	 * <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
	 * 中的《自建》应用即可查看到
	 * @return 返回重定向的地址
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public String getRedirectUriByAppidAndAgentid(String appid, String agentid) throws OAuth2AuthenticationException {
		WeChatWorkWebsiteProperties.WeChatWorkWebsite weChatWorkWebsite = getWeChatWorkWebsiteByAppidAndAgentid(appid,
				agentid);
		String redirectUriPrefix = weChatWorkWebsite.getRedirectUriPrefix();

		if (StringUtils.hasText(redirectUriPrefix)) {
			return UriUtils.encode(redirectUriPrefix + "/" + appid + "/" + agentid, StandardCharsets.UTF_8);
		}
		else {
			OAuth2Error error = new OAuth2Error(OAuth2WeChatWorkWebsiteEndpointUtils.ERROR_CODE, "重定向地址前缀不能为空", null);
			throw new RedirectUriWeChatWorkException(error);
		}
	}

	/**
	 * 生成状态码
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param agentid 访问
	 * <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
	 * @return 返回生成的授权码
	 */
	@Override
	public String stateGenerate(HttpServletRequest request, HttpServletResponse response, String appid,
			String agentid) {
		return UUID.randomUUID().toString();
	}

	/**
	 * 储存绑定参数
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param agentid 访问
	 * <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
	 * @param state 状态码
	 * @param binding 绑定参数
	 */
	@Override
	public void storeBinding(HttpServletRequest request, HttpServletResponse response, String appid, String agentid,
			String state, String binding) {

	}

	/**
	 * 储存操作用户
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param agentid 访问
	 * <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
	 * @param state 状态码
	 * @param binding 绑定参数
	 */
	@Override
	public void storeUsers(HttpServletRequest request, HttpServletResponse response, String appid, String agentid,
			String state, String binding) {

	}

	/**
	 * 状态码验证（返回 {@link Boolean#FALSE} 时，将终止后面需要执行的代码）
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param code 授权码
	 * @param state 状态码
	 * @return 返回 状态码验证结果
	 */
	@Override
	public boolean stateValid(HttpServletRequest request, HttpServletResponse response, String appid, String agentid,
			String code, String state) {
		return true;
	}

	/**
	 * 获取 绑定参数
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param code 授权码
	 * @param state 状态码
	 * @return 返回 绑定参数
	 */
	@Override
	public String getBinding(HttpServletRequest request, HttpServletResponse response, String appid, String agentid,
			String code, String state) {
		return null;
	}

	/**
	 * 根据 appid 获取 企业微信 扫码授权登录属性配置
	 * @param appid 公众号ID
	 * @param agentid 访问
	 * <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
	 * @return 返回 企业微信 扫码授权登录属性配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public WeChatWorkWebsiteProperties.WeChatWorkWebsite getWeChatWorkWebsiteByAppidAndAgentid(String appid,
			String agentid) throws OAuth2AuthenticationException {
		List<WeChatWorkWebsiteProperties.WeChatWorkWebsite> list = weChatWorkWebsiteProperties.getList();
		if (list == null) {
			OAuth2Error error = new OAuth2Error(OAuth2WeChatWorkWebsiteEndpointUtils.ERROR_CODE, "appid 未配置", null);
			throw new AppidWeChatWorkException(error);
		}

		for (WeChatWorkWebsiteProperties.WeChatWorkWebsite weChatWorkWebsite : list) {
			if (appid.equals(weChatWorkWebsite.getAppid())) {
				return weChatWorkWebsite;
			}
		}
		OAuth2Error error = new OAuth2Error(OAuth2WeChatWorkWebsiteEndpointUtils.ERROR_CODE, "未匹配到 appid", null);
		throw new AppidWeChatWorkException(error);
	}

	/**
	 * 获取 OAuth 2.1 授权 Token（如果不想执行此方法后面的内容，可返回 null）
	 * @param request 请求
	 * @param response 响应
	 * @param tokenUrlPrefix 获取 Token URL 前缀
	 * @param tokenUrl Token URL
	 * @param uriVariables 参数
	 * @return 返回 OAuth 2.1 授权 Token
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@SuppressWarnings("AlibabaLowerCamelCaseVariableNaming")
	@Override
	public OAuth2AccessTokenResponse getOAuth2AccessTokenResponse(HttpServletRequest request,
			HttpServletResponse response, String tokenUrlPrefix, String tokenUrl, Map<String, String> uriVariables)
			throws OAuth2AuthenticationException {

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<?> httpEntity = new HttpEntity<>(httpHeaders);

		RestTemplate restTemplate = new RestTemplate();

		List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
		messageConverters.add(5, new OAuth2AccessTokenResponseHttpMessageConverter());

		return restTemplate.postForObject(tokenUrlPrefix + tokenUrl, httpEntity, OAuth2AccessTokenResponse.class,
				uriVariables);
	}

	/**
	 * 根据 AppID、code、accessTokenUrl 获取Token
	 * @param appid AppID
	 * @param agentid 访问
	 * <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
	 * @param code 授权码
	 * @param state 状态码
	 * @param binding 是否绑定，需要使用者自己去拓展
	 * @param userinfoUrl 通过 access_token 获取用户个人信息
	 * @param getUserUrl 读取成员
	 * @param convertToOpenidUrl 使用 userid 换取 openid
	 * @param remoteAddress 用户IP
	 * @param sessionId SessionID
	 * @return 返回 微信授权结果
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public WeChatWorkWebsiteTokenResponse getAccessTokenResponse(String appid, String agentid, String code,
			String state, String binding, String accessTokenUrl, String userinfoUrl, String getUserUrl,
			String convertToOpenidUrl, String remoteAddress, String sessionId) throws OAuth2AuthenticationException {
		Map<String, String> uriVariables = new HashMap<>(8);
		uriVariables.put(OAuth2WeChatWorkParameterNames.APPID, appid);

		String secret = getSecretByAppid(appid, agentid);

		uriVariables.put(OAuth2WeChatWorkParameterNames.SECRET, secret);

		RestTemplate restTemplate = new RestTemplate();
		List<HttpMessageConverter<?>> messageConverters = restTemplate.getMessageConverters();
		messageConverters.set(1, new StringHttpMessageConverter(StandardCharsets.UTF_8));

		String forObject = restTemplate.getForObject(accessTokenUrl, String.class, uriVariables);

		WeChatWorkWebsiteTokenResponse weChatWorkWebsiteTokenResponse;
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		try {
			weChatWorkWebsiteTokenResponse = objectMapper.readValue(forObject, WeChatWorkWebsiteTokenResponse.class);
		}
		catch (JsonProcessingException e) {
			OAuth2Error error = new OAuth2Error(OAuth2WeChatWorkWebsiteEndpointUtils.ERROR_CODE,
					"使用 企业微信 扫码授权登录 授权code：" + code + " 获取Token异常",
					OAuth2WeChatWorkWebsiteEndpointUtils.AUTH_WEBSITE_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		Integer errcode = weChatWorkWebsiteTokenResponse.getErrcode();
		String accessToken = weChatWorkWebsiteTokenResponse.getAccessToken();
		if (errcode != 0) {
			OAuth2Error error = new OAuth2Error(weChatWorkWebsiteTokenResponse.getErrcode() + "",
					weChatWorkWebsiteTokenResponse.getErrmsg(), OAuth2WeChatWorkWebsiteEndpointUtils.AUTH_WEBSITE_URI);
			throw new OAuth2AuthenticationException(error);
		}

		Map<String, String> map = new HashMap<>(4);
		map.put(OAuth2ParameterNames.ACCESS_TOKEN, accessToken);
		map.put(OAuth2ParameterNames.CODE, code);

		String string = restTemplate.getForObject(userinfoUrl, String.class, map);
		try {
			WeChatWorkWebsiteTokenResponse.User response = objectMapper.readValue(string,
					WeChatWorkWebsiteTokenResponse.User.class);
			weChatWorkWebsiteTokenResponse.setUserid(response.getUserid());
		}
		catch (JsonProcessingException e) {
			OAuth2Error error = new OAuth2Error(OAuth2WeChatWorkWebsiteEndpointUtils.ERROR_CODE,
					"使用 企业微信 扫码授权登录 获取用户个人信息异常：", OAuth2WeChatWorkWebsiteEndpointUtils.AUTH_WEBSITE_URI);
			throw new OAuth2AuthenticationException(error, e);
		}

		String userid = weChatWorkWebsiteTokenResponse.getUserid();
		if (userid != null) {

			Map<String, String> uriVariablesMap = new HashMap<>(4);
			uriVariablesMap.put(OAuth2ParameterNames.ACCESS_TOKEN, accessToken);
			uriVariablesMap.put(OAuth2WeChatWorkParameterNames.USERID, userid);

			String getForObject = restTemplate.getForObject(getUserUrl, String.class, uriVariablesMap);
			try {
				WeChatWorkWebsiteTokenResponse.User response = objectMapper.readValue(getForObject,
						WeChatWorkWebsiteTokenResponse.User.class);
				weChatWorkWebsiteTokenResponse.setUser(response);
			}
			catch (JsonProcessingException e) {
				OAuth2Error error = new OAuth2Error(OAuth2WeChatWorkWebsiteEndpointUtils.ERROR_CODE,
						"使用 企业微信 扫码授权登录 读取成员异常：", OAuth2WeChatWorkWebsiteEndpointUtils.AUTH_WEBSITE_URI);
				throw new OAuth2AuthenticationException(error, e);
			}

			HttpHeaders httpHeaders = new HttpHeaders();
			httpHeaders.setContentType(MediaType.APPLICATION_JSON);
			Map<String, String> body = new HashMap<>(4);
			body.put(OAuth2WeChatWorkParameterNames.USERID, userid);
			HttpEntity<Map<String, String>> httpEntity = new HttpEntity<>(body, httpHeaders);

			String post = restTemplate.postForObject(convertToOpenidUrl, httpEntity, String.class, uriVariablesMap);
			try {
				WeChatWorkWebsiteTokenResponse.User response = objectMapper.readValue(post,
						WeChatWorkWebsiteTokenResponse.User.class);
				weChatWorkWebsiteTokenResponse.setUser(response);
				weChatWorkWebsiteTokenResponse.setOpenid(response.getOpenid());
			}
			catch (JsonProcessingException e) {
				OAuth2Error error = new OAuth2Error(OAuth2WeChatWorkWebsiteEndpointUtils.ERROR_CODE,
						"使用 企业微信 扫码授权登录 使用userid获取openid异常：", OAuth2WeChatWorkWebsiteEndpointUtils.AUTH_WEBSITE_URI);
				throw new OAuth2AuthenticationException(error, e);
			}
		}

		return weChatWorkWebsiteTokenResponse;
	}

	/**
	 * 构建 企业微信 扫码授权登录 认证信息
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param details 登录信息
	 * @param appid AppID
	 * @param code 授权码
	 * @param openid 用户唯一标识
	 * @param credentials 证书
	 * @param unionid 多账户用户唯一标识
	 * @param accessToken 授权凭证
	 * @param expiresIn 过期时间
	 * @return 返回 认证信息
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String code, String userid,
			String openid, Object credentials, String unionid, String accessToken, Integer expiresIn)
			throws OAuth2AuthenticationException {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(weChatWorkWebsiteProperties.getDefaultRole());
		authorities.add(authority);
		User user = new User(openid, accessToken, authorities);

		UsernamePasswordAuthenticationToken principal = UsernamePasswordAuthenticationToken.authenticated(user, null,
				user.getAuthorities());

		WeChatWorkWebsiteAuthenticationToken authenticationToken = new WeChatWorkWebsiteAuthenticationToken(authorities,
				clientPrincipal, principal, user, additionalParameters, details, appid, code, openid);

		authenticationToken.setCredentials(credentials);
		authenticationToken.setUnionid(unionid);

		return authenticationToken;
	}

	/**
	 * 授权成功重定向方法
	 * @param request 请求
	 * @param response 响应
	 * @param uriVariables 参数
	 * @param oauth2AccessTokenResponse OAuth2.1 授权 Token
	 * @param weChatWorkWebsite 企业微信 扫码授权登录 配置
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse,
			WeChatWorkWebsiteProperties.WeChatWorkWebsite weChatWorkWebsite) throws OAuth2AuthenticationException {

		OAuth2AccessToken accessToken = oauth2AccessTokenResponse.getAccessToken();

		try {
			response.sendRedirect(weChatWorkWebsite.getSuccessUrl() + "?" + weChatWorkWebsite.getParameterName() + "="
					+ accessToken.getTokenValue());
		}
		catch (IOException e) {
			OAuth2Error error = new OAuth2Error(OAuth2WeChatWorkWebsiteEndpointUtils.ERROR_CODE, "企业微信 扫码授权登录重定向异常",
					null);
			throw new RedirectWeChatWorkException(error, e);
		}

	}

	public String getSecretByAppid(String appid, String agentid) {
		Assert.notNull(appid, "appid 不能为 null");
		WeChatWorkWebsiteProperties.WeChatWorkWebsite weChatWorkWebsite = getWeChatWorkWebsiteByAppidAndAgentid(appid,
				agentid);
		return weChatWorkWebsite.getSecret();
	}

}
