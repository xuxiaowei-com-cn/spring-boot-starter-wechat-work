package org.springframework.security.oauth2.server.authorization.properties;

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

import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * 企业微信 扫码授权登录 属性配置类
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Data
@Component
@ConfigurationProperties("wechat.work.website")
public class WeChatWorkWebsiteProperties {

	/**
	 * 企业微信 扫码授权登录 属性配置列表
	 */
	private List<WeChatWorkWebsite> list;

	/**
	 * 默认企业微信 扫码授权登录 的权限
	 */
	private String defaultRole;

	/**
	 * 默认 AppID
	 */
	@Getter(AccessLevel.NONE)
	private String defaultAppid;

	public String getDefaultAppid() {
		if (StringUtils.hasText(defaultAppid)) {
			return defaultAppid;
		}
		if (list == null) {
			return null;
		}
		if (list.size() > 0) {
			return list.get(0).appid;
		}
		return null;
	}

	/**
	 * 默认 Agentid
	 */
	@Getter(AccessLevel.NONE)
	private String getDefaultAgentid;

	public String getGetDefaultAgentid() {
		if (StringUtils.hasText(getDefaultAgentid)) {
			return getDefaultAgentid;
		}
		if (list == null) {
			return null;
		}
		if (list.size() > 0) {
			return list.get(0).agentid;
		}
		return null;
	}

	/**
	 * 企业微信 扫码授权登录 属性配置类
	 *
	 * @author xuxiaowei
	 * @since 0.0.1
	 */
	@Data
	public static class WeChatWorkWebsite {

		/**
		 * AppID，企业ID，见：<a href=
		 * "https://work.weixin.qq.com/wework_admin/frame#profile">企业信息</a>
		 */
		private String appid;

		/**
		 * 访问 <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
		 * 中的《自建》应用即可查看到
		 */
		private String agentid;

		/**
		 * AppSecret
		 */
		private String secret;

		/**
		 * 重定向的网址前缀（程序使用时，会在后面拼接 /{@link #appid}）
		 */
		private String redirectUriPrefix;

		/**
		 * OAuth2 客户ID
		 */
		private String clientId;

		/**
		 * OAuth2 客户秘钥
		 */
		private String clientSecret;

		/**
		 * 获取 Token URL 前缀
		 */
		private String tokenUrlPrefix;

		/**
		 * 授权范围
		 */
		private String scope;

		/**
		 * 登录成功后重定向的URL
		 */
		private String successUrl;

		/**
		 * 登录成功后重定向的URL OAuth2.1 授权 Token Name
		 */
		private String parameterName = "access_token";

	}

}
