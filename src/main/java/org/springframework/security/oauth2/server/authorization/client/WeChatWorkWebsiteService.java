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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.properties.WeChatWorkWebsiteProperties;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.util.Map;

/**
 * 企业微信 扫码授权登录 账户服务接口
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see RegisteredClientRepository
 * @see InMemoryRegisteredClientRepository
 * @see JdbcRegisteredClientRepository
 */
public interface WeChatWorkWebsiteService {

	/**
	 * 根据 appid 获取重定向的地址
	 * @param appid 开放平台 网站应用 ID
	 * @param agentid 访问
	 * <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
	 * @return 返回重定向的地址
	 * @throws OAuth2AuthenticationException OAuth 2.1 可处理的异常，可使用
	 * {@link OAuth2AuthorizationServerConfigurer#tokenEndpoint(Customizer)} 中的
	 * {@link OAuth2TokenEndpointConfigurer#errorResponseHandler(AuthenticationFailureHandler)}
	 * 拦截处理此异常
	 */
	String getRedirectUriByAppidAndAgentid(String appid, String agentid) throws OAuth2AuthenticationException;

	/**
	 * 生成状态码
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param agentid 访问
	 * <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
	 * 中的《自建》应用即可查看到
	 * @return 返回生成的授权码
	 */
	String stateGenerate(HttpServletRequest request, HttpServletResponse response, String appid, String agentid);

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
	void storeBinding(HttpServletRequest request, HttpServletResponse response, String appid, String agentid,
			String state, String binding);

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
	void storeUsers(HttpServletRequest request, HttpServletResponse response, String appid, String agentid,
			String state, String binding);

	/**
	 * 状态码验证（返回 {@link Boolean#FALSE} 时，将终止后面需要执行的代码）
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param code 授权码
	 * @param state 状态码
	 * @return 返回 状态码验证结果
	 */
	boolean stateValid(HttpServletRequest request, HttpServletResponse response, String appid, String agentid,
			String code, String state);

	/**
	 * 获取 绑定参数
	 * @param request 请求
	 * @param response 响应
	 * @param appid 开放平台 网站应用 ID
	 * @param code 授权码
	 * @param state 状态码
	 * @return 返回 绑定参数
	 */
	String getBinding(HttpServletRequest request, HttpServletResponse response, String appid, String agentid,
			String code, String state);

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
	WeChatWorkWebsiteProperties.WeChatWorkWebsite getWeChatWorkWebsiteByAppidAndAgentid(String appid, String agentid)
			throws OAuth2AuthenticationException;

	/**
	 * 获取 OAuth 2.1 授权 Token（如果不想执行此方法后面的内容，可返回 null）
	 * @param request 请求
	 * @param response 响应
	 * @param clientId 客户ID
	 * @param clientSecret 客户凭证
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
	OAuth2AccessTokenResponse getOAuth2AccessTokenResponse(HttpServletRequest request, HttpServletResponse response,
			String clientId, String clientSecret, String tokenUrlPrefix, String tokenUrl,
			Map<String, String> uriVariables) throws OAuth2AuthenticationException;

	/**
	 * 根据 AppID、code、accessTokenUrl 获取Token
	 * @param appid AppID
	 * @param agentid 访问
	 * <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
	 * @param code 授权码
	 * @param state 状态码
	 * @param binding 是否绑定，需要使用者自己去拓展
	 * @param accessTokenUrl 通过 code 换取网页授权 access_token 的 URL
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
	WeChatWorkWebsiteTokenResponse getAccessTokenResponse(String appid, String agentid, String code, String state,
			String binding, String accessTokenUrl, String userinfoUrl, String getUserUrl, String convertToOpenidUrl,
			String remoteAddress, String sessionId) throws OAuth2AuthenticationException;

	/**
	 * 构建 企业微信 扫码授权登录 认证信息
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 * @param details 登录信息
	 * @param appid AppID
	 * @param agentid 应用ID
	 * @param code 授权码
	 * @param userid 用户ID
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
	AbstractAuthenticationToken authenticationToken(Authentication clientPrincipal,
			Map<String, Object> additionalParameters, Object details, String appid, String agentid, String code,
			String userid, String openid, Object credentials, String unionid, String accessToken, Integer expiresIn)
			throws OAuth2AuthenticationException;

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
	void sendRedirect(HttpServletRequest request, HttpServletResponse response, Map<String, String> uriVariables,
			OAuth2AccessTokenResponse oauth2AccessTokenResponse,
			WeChatWorkWebsiteProperties.WeChatWorkWebsite weChatWorkWebsite) throws OAuth2AuthenticationException;

}
