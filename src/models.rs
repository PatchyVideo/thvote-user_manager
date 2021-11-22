
use std::fmt;

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use chrono::{Utc};
use jwt_simple::prelude::{Claims, Duration, ECDSAP256kKeyPairLike, ES256kKeyPair, UnixTimeStamp};
use serde::{Serialize, Deserialize};
use bson::{DateTime, oid::ObjectId};

use crate::context::LoginSession;

#[derive(Serialize)]
pub struct ErrorResponse {
	code: u16,
	error: String,
	message: String,
	detail: Option<String>,
	sid: Option<String>,
	nickname: Option<String>
}

#[derive(Debug, Clone)]
pub enum ServiceError {
	Unknown{ detail: String },
	UserNotFound,
	AuthorizationFailed,
	IncorrectPassword,
	IncorrectVerifyCode,
	UserAlreadyExists,
	UserNotVerified,
	LoginMethodNotSupported,
	TooFrequent,
	RedirectToSignup{ sid: String, nickname: Option<String> },
	UpstreamRequestFailed { url: String }
}
impl std::error::Error for ServiceError {}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ServiceError {
	pub fn name(&self) -> String {
		match self {
			ServiceError::Unknown{..} => "Unknown".to_string(),
			ServiceError::UserNotFound => "UserNotFound".to_string(),
			ServiceError::AuthorizationFailed => "AuthorizationFailed".to_string(),
			ServiceError::IncorrectPassword => "IncorrectPassword".to_string(),
			ServiceError::IncorrectVerifyCode => "IncorrectVerifyCode".to_string(),
			ServiceError::UserAlreadyExists => "UserAlreadyExists".to_string(),
			ServiceError::UserNotVerified => "UserNotVerified".to_string(),
			ServiceError::LoginMethodNotSupported => "LoginMethodNotSupported".to_string(),
			ServiceError::TooFrequent => "TooFrequent".to_string(),
			ServiceError::RedirectToSignup { sid, nickname } => "RedirectToSignup".to_string(),
    		ServiceError::UpstreamRequestFailed { url } => "UpstreamRequestFailed".to_string(),
		}
	}
}
impl ResponseError for ServiceError {
	fn status_code(&self) -> StatusCode {
		match self {
			ServiceError::Unknown{..} => StatusCode::INTERNAL_SERVER_ERROR,
			ServiceError::UserNotFound => StatusCode::NOT_FOUND,
			ServiceError::AuthorizationFailed => StatusCode::UNAUTHORIZED,
			ServiceError::IncorrectPassword => StatusCode::UNAUTHORIZED,
			ServiceError::IncorrectVerifyCode => StatusCode::UNAUTHORIZED,
			ServiceError::UserAlreadyExists => StatusCode::UNAUTHORIZED,
			ServiceError::UserNotVerified => StatusCode::UNAUTHORIZED,
			ServiceError::LoginMethodNotSupported => StatusCode::NOT_IMPLEMENTED,
			ServiceError::TooFrequent => StatusCode::TOO_MANY_REQUESTS,
			ServiceError::RedirectToSignup { sid, nickname } => StatusCode::UNAUTHORIZED,
    		ServiceError::UpstreamRequestFailed { url } => StatusCode::REQUEST_TIMEOUT,
		}
	}

	fn error_response(&self) -> HttpResponse {
		let status_code = self.status_code();
		let (sid, nickname) = match self {
			ServiceError::RedirectToSignup { sid, nickname } => (Some(sid.clone()), nickname.clone()),
			_ => (None, None)
		};
		let detail = match self {
			ServiceError::Unknown { detail } => Some(detail.clone()),
			_ => None
		};
		let error_response = ErrorResponse {
			code: status_code.as_u16(),
			message: self.to_string(),
			error: self.name(),
			detail: detail,
			sid: sid,
			nickname: nickname
		};
		HttpResponse::build(status_code).json(error_response)
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VoteTokenClaim {
	pub vote_id: Option<String>
}


#[derive(Clone, Serialize, Deserialize)]
/// 给前端的投票人
pub struct VoterFE {
	pub username: Option<String>,
	pub pfp: Option<String>,
	pub password: bool,
	pub phone: Option<String>,
	pub email: Option<String>,
	pub thbwiki: bool,
	pub patchyvideo: bool
}

/// 投票人
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Voter {
	#[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
	pub _id: Option<ObjectId>,
	pub phone: Option<String>,
	pub phone_verified: bool,
	pub email: Option<String>,
	pub email_verified: bool,
	/// Not required if THBWiki login or SMS login is used
	pub password_hashed: Option<String>,
	/// Used only in legacy login
	pub salt: Option<String>,
	/// 新版投票用户创建日期
	pub created_at: DateTime,
	pub nickname: Option<String>,
	pub signup_ip: Option<String>,
	pub qq_openid: Option<String>,
	pub pfp: Option<String>,
	pub thbwiki_uid: Option<String>
}

impl Voter {
	/// Generate a unqiue id connectted to voter for a given year
	pub fn generate_vote_id(&self, vote_year: u32) -> Result<String, ServiceError> {
		if self.phone_verified || self.email_verified {
			let id = self._id.as_ref().unwrap().clone().to_string();
			return Ok(format!("thvote-{}-{}", vote_year, id));
		}
		return Err(ServiceError::UserNotVerified);
	}
	/// Generate a signed JWT token for voting with
	/// 1. vote-id
	/// 2. valid since
	/// 3. valid until
	/// 4. scope (vote or login)
	pub fn generate_vote_token(&self, vote_year: u32, key: &ES256kKeyPair) -> Result<String, ServiceError> {
		let addtional_info = VoteTokenClaim {
			vote_id: Some(self.generate_vote_id(vote_year)?)
		};
		let claims = Claims::with_custom_claims_given_valid_period(addtional_info, UnixTimeStamp::new(1633060800, 0), Duration::from_hours(7 * 24))
			.with_audience("vote");
		Ok(key.sign(claims).unwrap())
	}
	/// Generate a signed JWT token for user space with
	/// 1. valid until
	/// 2. scope (vote or login)
	pub fn generate_user_auth(&self, key: &ES256kKeyPair) -> String {
		let addtional_info = VoteTokenClaim {
			vote_id: Some(self._id.as_ref().unwrap().clone().to_string())
		};
		let claims = Claims::with_custom_claims(addtional_info, Duration::from_hours(7 * 24)).
			with_audience("userspace");
		key.sign(claims).unwrap()
	}
	pub fn to_fe_voter(&self, key: &ES256kKeyPair) -> VoterFE {
		VoterFE {
			username: self.nickname.clone(),
			pfp: self.pfp.clone(),
			password: self.password_hashed.is_some(),
			phone: self.phone.clone(),
			email: self.email.clone(),
			thbwiki: false,
			patchyvideo: false
		}
	}
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EmptyJSON {
	
}
impl EmptyJSON {
	pub fn new() -> EmptyJSON {
		EmptyJSON {  }
	}
}


#[derive(Clone, Serialize, Deserialize)]
pub struct UserEventMeta {
    pub user_ip: String,
    pub additional_fingureprint: Option<String>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SendPhoneVerifyCodeRequest {
    pub phone: String,
    pub meta: UserEventMeta
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SendEmailVerifyCodeRequest {
    pub email: String,
    pub meta: UserEventMeta
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EmailLoginInputsForExistingVoters {
    pub email: String,
    pub password: String,
    pub meta: UserEventMeta
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EmailLoginInputs {
    pub email: String,
    pub nickname: Option<String>,
    pub verify_code: String,
    pub meta: UserEventMeta
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateEmailInputs {
	pub user_token: String,
    pub email: String,
    pub verify_code: String,
    pub meta: UserEventMeta
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdatePhoneInputs {
	pub user_token: String,
    pub phone: String,
    pub verify_code: String,
    pub meta: UserEventMeta
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpdatePasswordInputs {
	pub user_token: String,
    pub old_password: String,
    pub new_password: String,
    pub meta: UserEventMeta
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PhoneLoginInputs {
    pub phone: String,
    pub nickname: Option<String>,
    pub verify_code: String,
    pub meta: UserEventMeta
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginResults {
	/// 用户
	pub user: VoterFE,
	/// 投票token
	pub vote_token: String,
	/// 用户登录token
	pub session_token: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityLogEntry {
	SendEmail {
		created_at: DateTime,
		target_email: String,
		code: String,
		requester_ip: Option<String>,
		requester_additional_fingerprint: Option<String>
	},
	SendSMS {
		created_at: DateTime,
		target_phone: String,
		code: String,
		requester_ip: Option<String>,
		requester_additional_fingerprint: Option<String>
	},
	VoterCreation {
		created_at: DateTime,
		uid: ObjectId,
		email: Option<String>,
		phone: Option<String>,
		nickname: Option<String>,
		requester_ip: Option<String>,
		requester_additional_fingerprint: Option<String>
	},
	VoterLogin {
		created_at: DateTime,
		uid: ObjectId,
		email: Option<String>,
		phone: Option<String>,
		requester_ip: Option<String>,
		requester_additional_fingerprint: Option<String>
	}
}

