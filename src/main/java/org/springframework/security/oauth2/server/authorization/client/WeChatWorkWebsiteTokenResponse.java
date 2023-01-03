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

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * 通过 code 换取网页授权 access_token 返回值
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see <a href=
 * "https://developer.work.weixin.qq.com/document/path/91019">企业内部开发/服务端API/身份验证/扫码授权登录/构造扫码登录链接</a>
 */
@Data
public class WeChatWorkWebsiteTokenResponse implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * 网页授权接口调用凭证,注意：此access_token与基础支持的access_token不同
	 */
	@JsonProperty("access_token")
	private String accessToken;

	/**
	 * access_token接口调用凭证超时时间，单位（秒）
	 */
	@JsonProperty("expires_in")
	private Integer expiresIn;

	/**
	 * 非企业成员的标识，对当前企业唯一
	 */
	private String openid;

	/**
	 * 用户在开放平台的唯一标识符
	 */
	private String unionid;

	/**
	 * 成员UserID。若需要获得用户详情信息，可调用通讯录接口：<a href=
	 * "https://developer.work.weixin.qq.com/document/path/91437#10019">读取成员</a>
	 */
	private String userid;

	/**
	 * 错误码
	 */
	private Integer errcode;

	/**
	 * 错误信息
	 */
	private String errmsg;

	private User user;

	@Data
	public static class User {

		private Integer errcode;

		private String gender;

		private String externalPosition;

		@JsonProperty("is_leader_in_dept")
		private List<Integer> isLeaderInDept;

		@JsonProperty("direct_leader")
		private List<String> directLeader;

		private String userid;

		private String openid;

		private String thumbAvatar;

		private String alias;

		private String qrCode;

		private List<Integer> department;

		private String openUserid;

		private String bizMail;

		private String email;

		private List<Integer> order;

		private String address;

		private String mobile;

		private String errmsg;

		private String telephone;

		private String avatar;

		@JsonProperty("main_department")
		private Integer mainDepartment;

		private String name;

		private Extattr extattr;

		private String position;

		@JsonProperty("external_profile")
		private ExternalProfile externalProfile;

		private Integer status;

		private Integer isleader;

		private Integer enable;

		@JsonProperty("hide_mobile")
		private Integer hideMobile;

	}

	@Data
	public static class AttrsItem {

		private Web web;

		private String name;

		private Integer type;

		private Text text;

	}

	@Data
	public static class Extattr {

		private List<AttrsItem> attrs;

	}

	@Data
	public static class ExternalAttrItem {

		private String name;

		private Integer type;

		private Miniprogram miniprogram;

		private Web web;

		private Text text;

	}

	@Data
	public static class ExternalProfile {

		private WechatChannels wechatChannels;

		@JsonProperty("external_attr")
		private List<ExternalAttrItem> externalAttr;

		@JsonProperty("external_corp_name")
		private String externalCorpName;

	}

	@Data
	public static class WechatChannels {

		private String nickname;

		private Integer status;

	}

	@Data
	public static class Web {

		private String title;

		private String url;

	}

	@Data
	public static class Text {

		private String value;

	}

	@Data
	public static class Miniprogram {

		private String pagepath;

		private String appid;

		private String title;

	}

}
