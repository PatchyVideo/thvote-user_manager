use argon2::Config;
use bson::{doc, oid::ObjectId};
use rand::{RngCore, rngs::OsRng};
use redis::AsyncCommands;

use crate::{context::AppContext, models::ServiceError};


pub async fn update_email(ctx: &AppContext, uid: ObjectId, email: String, verify_code: String) -> Result<(), Box<dyn std::error::Error>> {
    let id = format!("email-verify-{}", email);
	let mut conn = ctx.redis_client.get_async_connection().await?;
	let expected_code: Option<String> = conn.get(&id).await?;
	if let None = expected_code {
		return Err(ServiceError::IncorrectVerifyCode.into());
	}
	let expected_code = expected_code.unwrap();
	if expected_code != verify_code {
		println!("{}", expected_code);
		return Err(ServiceError::IncorrectVerifyCode.into());
	}

    if let Some(voter) = ctx.voters_coll.find_one(doc! { "_id": uid.clone() }, None).await? {
        ctx.voters_coll.update_one(
            doc! { "_id": uid },
            doc! {
                "$set": {
                    "email": email,
                    "email_verified": true
                }
            },
            None).await?;
    } else {
        return Err(ServiceError::UserNotFound.into());
    }

    Ok(())
}

pub async fn update_phone(ctx: &AppContext, uid: ObjectId, phone: String, verify_code: String) -> Result<(), Box<dyn std::error::Error>> {
    let id = format!("phone-verify-{}", phone);
	let mut conn = ctx.redis_client.get_async_connection().await?;
	let expected_code: Option<String> = conn.get(&id).await?;
	if let None = expected_code {
		return Err(ServiceError::IncorrectVerifyCode.into());
	}
	let expected_code = expected_code.unwrap();
	if expected_code != verify_code {
		println!("{}", expected_code);
		return Err(ServiceError::IncorrectVerifyCode.into());
	}

    if let Some(voter) = ctx.voters_coll.find_one(doc! { "_id": uid.clone() }, None).await? {
        ctx.voters_coll.update_one(
            doc! { "_id": uid },
            doc! {
                "$set": {
                    "phone": phone,
                    "phone_verified": true
                }
            },
            None).await?;
    } else {
        return Err(ServiceError::UserNotFound.into());
    }

    Ok(())
}

pub async fn update_password(ctx: &AppContext, uid: ObjectId, old_password: String, new_password: String) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(voter) = ctx.voters_coll.find_one(doc! { "_id": uid.clone() }, None).await? {
        if let Some(password_hashed) = voter.password_hashed.as_ref() {
			if let Some(salt) = voter.salt.as_ref() {
				let pwrt = format!("{}{}", old_password, salt);
				if !bcrypt::verify(pwrt, password_hashed).ok().unwrap_or(false) {
					return Err(ServiceError::IncorrectPassword.into());
				} else {
					// legacy bcrypt verified
					// upgrade to argon2
					let mut salt = [0u8; 16];
					OsRng.fill_bytes(&mut salt);
					let new_password_hashed = argon2::hash_encoded(new_password.as_bytes(), &salt, &Config::default())?;
					let mut voter = voter.clone();
					voter.salt = None;
					voter.password_hashed = Some(new_password_hashed.clone());
					ctx.voters_coll.replace_one(doc! { "_id": uid.clone() }, voter.clone(), None).await?;
					return Ok(());
				}
			};
			if argon2::verify_encoded(password_hashed, old_password.as_bytes())? {
				let mut voter = voter.clone();
				let mut salt = [0u8; 16];
                OsRng.fill_bytes(&mut salt);
                let new_password_hashed = argon2::hash_encoded(new_password.as_bytes(), &salt, &Config::default())?;
                voter.salt = None;
                voter.password_hashed = Some(new_password_hashed.clone());
                ctx.voters_coll.replace_one(doc! { "_id": uid.clone() }, voter.clone(), None).await?;
                return Ok(());
			} else {
				return Err(Box::new(ServiceError::IncorrectPassword));
			};
		} else {
			return Err(Box::new(ServiceError::LoginMethodNotSupported));
		}
    };
    Ok(())
}


