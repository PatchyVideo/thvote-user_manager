
use std::fmt;

use serde::{Serialize, Deserialize};
use bson::{DateTime, oid::ObjectId};

#[derive(Debug, Clone)]
pub enum ServiceError {
	EmailNotFound,
	IncorrectPassword,
	EmailAlreadyExists
}
impl std::error::Error for ServiceError {}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// 投票人
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Voter {
	pub email: String,
	pub password_hashed: String,
	pub password_salt: Vec<u8>,
	/// 新版投票用户创建日期
	pub created_at: DateTime,
	/// 旧版创建日期
	pub legacy_created_at: Option<DateTime>,
	pub nickname: Option<String>,
	pub signup_ip: Option<String>,
	pub qq_openid: Option<String>
}

/// 投票的JWT
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VoteToken {
	/// 唯一的随机字符串
	pub nonce: String,
	/// 对应的邮箱
	pub email: String,
	/// 第几届
	pub vote_id: String
}
