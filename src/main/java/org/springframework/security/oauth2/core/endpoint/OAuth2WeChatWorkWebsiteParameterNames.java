package org.springframework.security.oauth2.core.endpoint;

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

/**
 * 企业微信 扫码授权登录 参数名称
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2ParameterNames 在 OAuth 参数注册表中定义并由授权端点、令牌端点和令牌撤销端点使用的标准和自定义（非标准）参数名称。
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public interface OAuth2WeChatWorkWebsiteParameterNames {

	/**
	 * AppID
	 *
	 * @see <a href=
	 * "https://developer.work.weixin.qq.com/document/path/91019">企业内部开发/服务端API/身份验证/扫码授权登录/构造扫码登录链接</a>
	 */
	String APPID = "appid";

	/**
	 * 访问 <a href="https://work.weixin.qq.com/wework_admin/frame#apps">应用管理/应用</a>
	 * 中的《自建》应用即可查看到
	 */
	String AGENTID = "agentid";

	/**
	 * AppSecret
	 *
	 * @see <a href=
	 * "https://developer.work.weixin.qq.com/document/path/91019">企业内部开发/服务端API/身份验证/扫码授权登录/构造扫码登录链接</a>
	 */
	String SECRET = "secret";

	/**
	 * 用户唯一标识
	 *
	 * @see <a href=
	 * "https://developer.work.weixin.qq.com/document/path/91019">企业内部开发/服务端API/身份验证/扫码授权登录/构造扫码登录链接</a>
	 */
	String OPENID = "openid";

	/**
	 * @see <a href=
	 * "https://developer.work.weixin.qq.com/document/path/91019">企业内部开发/服务端API/身份验证/扫码授权登录/构造扫码登录链接</a>
	 */
	String UNIONID = "unionid";

	/**
	 * 远程地址
	 */
	String REMOTE_ADDRESS = "remote_address";

	/**
	 * Session ID
	 */
	String SESSION_ID = "session_id";

	/**
	 * 是否绑定，需要使用者自己去拓展
	 */
	String BINDING = "binding";

	String USERID = "userid";

}
