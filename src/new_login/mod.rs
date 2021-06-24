use crate::{context::AppContext, models::{ServiceError, Voter}};
use argon2::Config;
use mongodb::bson::{doc};
use chrono::Utc;
use chrono::prelude::*;
use rand::{Rng, rngs::OsRng, RngCore};

pub async fn check_email_availability(ctx: &AppContext, email: String) -> Result<bool, Box<dyn std::error::Error>> {
	Ok(ctx.voters_coll.find_one(doc! { "email": email }, None).await?.is_none())
}

pub async fn signup(ctx: &AppContext, email: String, password: String, nickname: Option<String>, signup_ip: Option<String>, sid: Option<String>) -> Result<Voter, Box<dyn std::error::Error>> {
	if let None = ctx.voters_coll.find_one(doc! { "email": email.clone() }, None).await? {
		let mut salt = [0u8; 16];
		OsRng.fill_bytes(&mut salt);
		let password_hashed = argon2::hash_encoded(password.as_bytes(), &salt, &Config::default())?;
		let mut voter = Voter {
			email: email,
			email_verified: false,
			password_hashed: Some(password_hashed),
			created_at: bson::DateTime(Utc::now()),
			legacy_created_at: None,
			nickname: nickname,
			signup_ip: signup_ip,
			qq_openid: None,
			thbwiki_uid: None
		};
		if let Some(sid) = sid {
			if let Some(sess) = ctx.get_login_session(&sid).await {
				if let Some(thbwiki_uid) = sess.thbwiki_uid {
					voter.thbwiki_uid = Some(thbwiki_uid);
				}
				// TODO: QQ
			}
		}
		ctx.voters_coll.insert_one(voter.clone(), None).await?;
		Ok(voter)
	} else {
		Err(Box::new(ServiceError::EmailAlreadyExists))
	}
}

pub async fn login(ctx: &AppContext, email: String, password: String, sid: Option<String>) -> Result<Voter, Box<dyn std::error::Error>> {
	if let Some(voter) = ctx.voters_coll.find_one(doc! { "email": email.clone() }, None).await? {
		if let Some(password_hashed) = voter.password_hashed.as_ref() {
			if argon2::verify_encoded(password_hashed, password.as_bytes())? {
				let mut voter = voter.clone();
				if let Some(sid) = sid {
					if let Some(sess) = ctx.get_login_session(&sid).await {
						if let Some(thbwiki_uid) = sess.thbwiki_uid {
							voter.thbwiki_uid = Some(thbwiki_uid);
						}
						// TODO: QQ
						ctx.voters_coll.replace_one(doc! { "email": email.clone() }, voter.clone(), None).await?;
					}
				}
				Ok(voter)
			} else {
				Err(Box::new(ServiceError::IncorrectPassword))
			}
		} else {
			Err(Box::new(ServiceError::LoginMethodNotSupported))
		}
	} else {
		Err(Box::new(ServiceError::EmailNotFound))
	}
}
