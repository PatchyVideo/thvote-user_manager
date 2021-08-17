use std::{fmt::format, ops::RangeInclusive};

use crate::{context::AppContext, models::{ServiceError, Voter}};
use argon2::Config;
use mongodb::bson::{doc};
use chrono::Utc;
use chrono::prelude::*;
use rand::{Rng, RngCore, distributions::uniform::SampleRange, rngs::OsRng};
use rand::distributions::{Distribution, Uniform};
use redis::AsyncCommands;


pub async fn login_email_password(ctx: &AppContext, email: String, password: String, ip: Option<String>, additional_fingerprint: Option<String>, sid: Option<String>) -> Result<Voter, Box<dyn std::error::Error>> {
	if let Some(voter) = ctx.voters_coll.find_one(doc! { "email": email.clone() }, None).await? {
		if let Some(password_hashed) = voter.password_hashed.as_ref() {
			if argon2::verify_encoded(password_hashed, password.as_bytes())? {
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
				}
				Ok(voter)
			} else {
				Err(Box::new(ServiceError::IncorrectPassword))
			}
		} else {
			Err(Box::new(ServiceError::LoginMethodNotSupported))
		}
	} else {
		Err(Box::new(ServiceError::UserNotFound))
	}
}
