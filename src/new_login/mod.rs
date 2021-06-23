use crate::{context::AppContext, models::{ServiceError, Voter}};
use argon2::Config;
use mongodb::bson::{doc};
use chrono::Utc;
use chrono::prelude::*;
use rand::{Rng, rngs::OsRng, RngCore};

pub async fn check_email_availability(ctx: &AppContext, email: String) -> Result<bool, Box<dyn std::error::Error>> {
	Ok(ctx.voters_coll.find_one(doc! { "email": email }, None).await?.is_none())
}

pub async fn signup(ctx: &AppContext, email: String, password: String, nickname: Option<String>, signup_ip: Option<String>) -> Result<Voter, Box<dyn std::error::Error>> {
	if let None = ctx.voters_coll.find_one(doc! { "email": email.clone() }, None).await? {
		let mut salt = [0u8; 16];
		OsRng.fill_bytes(&mut salt);
		let password_hashed = argon2::hash_encoded(password.as_bytes(), &salt, &Config::default())?;
		Ok(Voter {
			email: email,
			password_hashed: password_hashed,
			password_salt: salt.to_vec(),
			created_at: bson::DateTime(Utc::now()),
			legacy_created_at: None,
			nickname: nickname,
			signup_ip: signup_ip,
			qq_openid: None,
		})
	} else {
		Err(Box::new(ServiceError::EmailAlreadyExists))
	}
}

pub async fn login(ctx: &AppContext, email: String, password: String) -> Result<Voter, Box<dyn std::error::Error>> {
	if let Some(voter) = ctx.voters_coll.find_one(doc! { "email": email }, None).await? {
		if argon2::verify_encoded(&voter.password_hashed, password.as_bytes())? {
			Ok(voter)
		} else {
			Err(Box::new(ServiceError::IncorrectPassword))
		}
	} else {
		Err(Box::new(ServiceError::EmailNotFound))
	}
}
