package org.springframework.security.oauth2.server.authorization.http;

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

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2WeChatWorkWebsiteParameterNames;
import org.springframework.security.oauth2.server.authorization.client.WeChatWorkWebsiteService;
import org.springframework.security.oauth2.server.authorization.properties.WeChatWorkWebsiteProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 企业微信 扫码授权登录 跳转到微信授权页面
 *
 * @see <a href=
 * "https://developer.work.weixin.qq.com/document/path/91019">企业内部开发/服务端API/身份验证/扫码授权登录/构造扫码登录链接</a>
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Data
@EqualsAndHashCode(callSuper = true)
@Component
public class WeChatWorkWebsiteAuthorizeHttpFilter extends HttpFilter {

	public static final String PREFIX_URL = "/wechat-work/website/authorize";

	public static final String AUTHORIZE_URL = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=%s&agentid=%s&redirect_uri=%s&state=%s";

	private WeChatWorkWebsiteProperties weChatWorkWebsiteProperties;

	private WeChatWorkWebsiteService weChatWorkWebsiteService;

	/**
	 * 企业微信 扫码授权登录 授权前缀
	 */
	private String prefixUrl = PREFIX_URL;

	@Autowired
	public void setWeChatWorkWebsiteProperties(WeChatWorkWebsiteProperties weChatWorkWebsiteProperties) {
		this.weChatWorkWebsiteProperties = weChatWorkWebsiteProperties;
	}

	@Autowired
	public void setWeChatWorkWebsiteService(WeChatWorkWebsiteService weChatWorkWebsiteService) {
		this.weChatWorkWebsiteService = weChatWorkWebsiteService;
	}

	@Override
	protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String requestUri = request.getRequestURI();
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean match = antPathMatcher.match(prefixUrl + "/*/*", requestUri);
		if (match) {
			log.info("requestUri：{}", requestUri);

			String replace = requestUri.replace(prefixUrl + "/", "");
			String[] split = replace.split("/");
			String appid = split[0];
			String agentid = split[1];

			String redirectUri = weChatWorkWebsiteService.getRedirectUriByAppidAndAgentid(appid, agentid);

			String binding = request.getParameter(OAuth2WeChatWorkWebsiteParameterNames.BINDING);

			String state = weChatWorkWebsiteService.stateGenerate(request, response, appid, agentid);
			weChatWorkWebsiteService.storeBinding(request, response, appid, agentid, state, binding);
			weChatWorkWebsiteService.storeUsers(request, response, appid, agentid, state, binding);

			String url = String.format(AUTHORIZE_URL, appid, agentid, redirectUri, state);

			log.info("redirectUrl：{}", url);

			response.sendRedirect(url);
			return;
		}

		super.doFilter(request, response, chain);
	}

}
