use std::{fmt::format, ops::RangeInclusive};

use crate::{context::AppContext, models::{ServiceError, Voter}};
use argon2::Config;
use mongodb::bson::{doc};
use chrono::Utc;
use chrono::prelude::*;
use rand::{Rng, RngCore, distributions::uniform::SampleRange, rngs::OsRng};
use rand::distributions::{Distribution, Uniform};
use redis::AsyncCommands;

pub async fn check_email_availability(ctx: &AppContext, email: String) -> Result<bool, Box<dyn std::error::Error>> {
	Ok(ctx.voters_coll.find_one(doc! { "email": email }, None).await?.is_none())
}

// pub async fn signup_email_old(ctx: &AppContext, email: String, password: String, ip: Option<String>, sid: Option<String>) -> Result<Voter, Box<dyn std::error::Error>> {
// 	if let None = ctx.voters_coll.find_one(doc! { "email": email.clone() }, None).await? {
// 		let mut salt = [0u8; 16];
// 		OsRng.fill_bytes(&mut salt);
// 		let password_hashed = argon2::hash_encoded(password.as_bytes(), &salt, &Config::default())?;
// 		let mut voter = Voter {
// 			_id: None,
// 			email: Some(email),
// 			email_verified: false,
// 			phone: None,
// 			phone_verified: false,
// 			password_hashed: Some(password_hashed),
// 			created_at: bson::DateTime(Utc::now()),
// 			legacy_created_at: None,
// 			nickname: nickname,
// 			signup_ip: ip,
// 			qq_openid: None,
// 			thbwiki_uid: None
// 		};
// 		if let Some(sid) = sid {
// 			if let Some(sess) = ctx.get_login_session(&sid).await {
// 				if let Some(thbwiki_uid) = sess.thbwiki_uid {
// 					voter.thbwiki_uid = Some(thbwiki_uid);
// 				}
// 				if let Some(qq_openid) = sess.qq_openid {
// 					voter.qq_openid = Some(qq_openid);
// 				}
// 			}
// 		}
// 		let iid = ctx.voters_coll.insert_one(voter.clone(), None).await?;
// 		voter._id = Some(iid.inserted_id.as_object_id().unwrap().clone());
// 		Ok(voter)
// 	} else {
// 		Err(Box::new(ServiceError::UserAlreadyExists))
// 	}
// }

pub async fn signup_email(ctx: &AppContext, email: String, verify_code: String, nickname: Option<String>, ip: Option<String>, additional_fingerprint: Option<String>, sid: Option<String>) -> Result<Voter, Box<dyn std::error::Error>> {
	if let None = ctx.voters_coll.find_one(doc! { "email": email.clone() }, None).await? {
		let id = format!("email-verify-{}", email);
		let expected_code: String = ctx.redis_client.get_async_connection().await?.get(id).await?;
		if expected_code != verify_code {
			return Err(ServiceError::IncorrectVerifyCode.into());
		}
		let mut voter = Voter {
			_id: None,
			email: Some(email),
			email_verified: true,
			phone: None,
			phone_verified: false,
			password_hashed: None,
			salt: None,
			created_at: bson::DateTime(Utc::now()),
			legacy_created_at: None,
			nickname: nickname,
			signup_ip: ip,
			qq_openid: None,
			thbwiki_uid: None
		};
		if let Some(sid) = sid {
			if let Some(sess) = ctx.get_login_session(&sid).await {
				if let Some(thbwiki_uid) = sess.thbwiki_uid {
					voter.thbwiki_uid = Some(thbwiki_uid);
				}
				if let Some(qq_openid) = sess.qq_openid {
					voter.qq_openid = Some(qq_openid);
				}
			}
		}
		let iid = ctx.voters_coll.insert_one(voter.clone(), None).await?;
		voter._id = Some(iid.inserted_id.as_object_id().unwrap().clone());
		Ok(voter)
	} else {
		Err(Box::new(ServiceError::UserAlreadyExists))
	}
}

pub async fn login_email(ctx: &AppContext, email: String, verify_code: String, nickname: Option<String>, ip: Option<String>, additional_fingerprint: Option<String>, sid: Option<String>) -> Result<Voter, Box<dyn std::error::Error>> {
	if let Some(voter) = ctx.voters_coll.find_one(doc! { "email": email.clone() }, None).await? {
		let id = format!("email-verify-{}", email);
		let expected_code: String = ctx.redis_client.get_async_connection().await?.get(id).await?;
		if expected_code != verify_code {
			return Err(ServiceError::IncorrectVerifyCode.into());
		}
		let mut voter = voter.clone();
		if let Some(sid) = sid {
			if let Some(sess) = ctx.get_login_session(&sid).await {
				if let Some(thbwiki_uid) = sess.thbwiki_uid {
					voter.thbwiki_uid = Some(thbwiki_uid);
				}
				if let Some(qq_openid) = sess.qq_openid {
					voter.qq_openid = Some(qq_openid);
				}
				ctx.voters_coll.replace_one(doc! { "email": email.clone() }, voter.clone(), None).await?;
			}
		};
		Ok(voter)
	} else {
		signup_email(ctx, email, verify_code, nickname, ip, additional_fingerprint, sid).await
	}
}

pub async fn send_email(ctx: &AppContext, email: String) -> Result<(), Box<dyn std::error::Error>> {
	let id = format!("email-verify-{}", email);
	let id_guard = format!("email-verify-guard-{}", email);
	let mut redis_conn = ctx.redis_client.get_async_connection().await?;
	// check if 1 minutes has passed since last SMS to the same email is sent
	let guard: Option<String> = redis_conn.get(id_guard.clone()).await?;
	if let Some(guard) = guard {
		if guard == "guard" {
			return Err(ServiceError::TooFrequent.into());
		}
	}
	// generate 6 digits code
	let code_u32 = OsRng.gen_range(RangeInclusive::new(0u32,  999999u32));
	let code = format!("{:06}", code_u32);
	// store in redis, expires in 1 hour
	redis_conn.set_ex(id, code.clone(), 3600).await?;
	// store guard in redis, expires in 1 minutes
	redis_conn.set_ex(id_guard, "guard", 60).await?;
	// invoke SMS send service
	//todo!();
	println!(" -- [Email] Code = {}", code);
	Ok(())
}

pub async fn check_phone_availability(ctx: &AppContext, phone: String) -> Result<bool, Box<dyn std::error::Error>> {
	Ok(ctx.voters_coll.find_one(doc! { "phone": phone }, None).await?.is_none())
}

pub async fn signup_phone(ctx: &AppContext, phone: String, verify_code: String, nickname: Option<String>, ip: Option<String>, additional_fingerprint: Option<String>, sid: Option<String>) -> Result<Voter, Box<dyn std::error::Error>> {
	if let None = ctx.voters_coll.find_one(doc! { "phone": phone.clone() }, None).await? {
		let id = format!("phone-verify-{}", phone);
		let expected_code: String = ctx.redis_client.get_async_connection().await?.get(id).await?;
		if expected_code != verify_code {
			return Err(ServiceError::IncorrectVerifyCode.into());
		}
		let mut voter = Voter {
			_id: None,
			email: None,
			email_verified: false,
			phone: Some(phone),
			phone_verified: true,
			password_hashed: None,
			salt: None,
			created_at: bson::DateTime(Utc::now()),
			legacy_created_at: None,
			nickname: nickname,
			signup_ip: ip,
			qq_openid: None,
			thbwiki_uid: None
		};
		if let Some(sid) = sid {
			if let Some(sess) = ctx.get_login_session(&sid).await {
				if let Some(thbwiki_uid) = sess.thbwiki_uid {
					voter.thbwiki_uid = Some(thbwiki_uid);
				}
				if let Some(qq_openid) = sess.qq_openid {
					voter.qq_openid = Some(qq_openid);
				}
			}
		}
		let iid = ctx.voters_coll.insert_one(voter.clone(), None).await?;
		voter._id = Some(iid.inserted_id.as_object_id().unwrap().clone());
		Ok(voter)
	} else {
		Err(Box::new(ServiceError::UserAlreadyExists))
	}
}

pub async fn send_sms(ctx: &AppContext, phone: String) -> Result<(), Box<dyn std::error::Error>> {
	let id = format!("phone-verify-{}", phone);
	let id_guard = format!("phone-verify-guard-{}", phone);
	let mut redis_conn = ctx.redis_client.get_async_connection().await?;
	// check if 1 minute has passed since last SMS to the same phone is sent
	let guard: Option<String> = redis_conn.get(id_guard.clone()).await?;
	if let Some(guard) = guard {
		if guard == "guard" {
			return Err(ServiceError::TooFrequent.into());
		}
	}
	// generate 6 digits code
	let code_u32 = OsRng.gen_range(RangeInclusive::new(0u32,  999999u32));
	let code = format!("{:06}", code_u32);
	// store in redis, expires in 1 hour
	redis_conn.set_ex(id, code.clone(), 3600).await?;
	// store guard in redis, expires in 1 minutes
	redis_conn.set_ex(id_guard, "guard", 60).await?;
	// invoke SMS send service
	println!(" -- [SMS] Code = {}", code);
	// let req = crate::sms_service::SMSRequest {
	// 	code: code,
	// 	mobile: phone
	// };
	// let client = actix_web::client::Client::new();
	// let resp = client.post(format!("{}/v1/vote-code", crate::comm::SERVICE_SMS_ADDRESS)).send_json(&req).await?;
	// if resp.status().is_success() {
	// 	Ok(())
	// } else {
	// 	Err(ServiceError::UpstreamRequestFailed { url: format!("{}/v1/vote-code", crate::comm::SERVICE_SMS_ADDRESS) }.into())
	// }
	Ok(())
}

pub async fn login_phone(ctx: &AppContext, phone: String, verify_code: String, nickname: Option<String>, ip: Option<String>, additional_fingerprint: Option<String>, sid: Option<String>) -> Result<Voter, Box<dyn std::error::Error>> {
	if let Some(voter) = ctx.voters_coll.find_one(doc! { "phone": phone.clone() }, None).await? {
		let id = format!("phone-verify-{}", phone);
		let expected_code: String = ctx.redis_client.get_async_connection().await?.get(id).await?;
		if expected_code != verify_code {
			return Err(ServiceError::IncorrectVerifyCode.into());
		}
		
		let mut voter = voter.clone();
		if let Some(sid) = sid {
			if let Some(sess) = ctx.get_login_session(&sid).await {
				if let Some(thbwiki_uid) = sess.thbwiki_uid {
					voter.thbwiki_uid = Some(thbwiki_uid);
				}
				if let Some(qq_openid) = sess.qq_openid {
					voter.qq_openid = Some(qq_openid);
				}
				ctx.voters_coll.replace_one(doc! { "phone": phone.clone() }, voter.clone(), None).await?;
			}
		};
		Ok(voter)
	} else {
		signup_phone(ctx, phone, verify_code, nickname, ip, additional_fingerprint, sid).await
	}
}
