use argon2::Config;
use bson::{doc, oid::ObjectId};
use pvrustlib::ServiceError;
use rand::{RngCore, rngs::OsRng};
use redis::AsyncCommands;

use crate::{context::AppContext, common::SERVICE_NAME};


pub async fn update_email(ctx: &AppContext, uid: ObjectId, email: String, verify_code: String) -> Result<(), Box<dyn std::error::Error>> {
    let id = format!("email-verify-{}", email);
	let mut conn = ctx.redis_client.get_async_connection().await?;
	let expected_code: Option<String> = conn.get(&id).await?;
	if let None = expected_code {
		return Err(ServiceError::new_error_kind(SERVICE_NAME, "INCORRECT_VERIFY_CODE").into());
	}
	let expected_code = expected_code.unwrap();
	if expected_code != verify_code {
		println!("{}", expected_code);
		return Err(ServiceError::new_error_kind(SERVICE_NAME, "INCORRECT_VERIFY_CODE").into());
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
        return Err(ServiceError::new_not_found(SERVICE_NAME, None).into());
    }

    Ok(())
}

pub async fn update_phone(ctx: &AppContext, uid: ObjectId, phone: String, verify_code: String) -> Result<(), Box<dyn std::error::Error>> {
    let id = format!("phone-verify-{}", phone);
	let mut conn = ctx.redis_client.get_async_connection().await?;
	let expected_code: Option<String> = conn.get(&id).await?;
	if let None = expected_code {
		return Err(ServiceError::new_error_kind(SERVICE_NAME, "INCORRECT_VERIFY_CODE").into());
	}
	let expected_code = expected_code.unwrap();
	if expected_code != verify_code {
		println!("{}", expected_code);
		return Err(ServiceError::new_error_kind(SERVICE_NAME, "INCORRECT_VERIFY_CODE").into());
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
        return Err(ServiceError::new_not_found(SERVICE_NAME, None).into());
    }

    Ok(())
}

pub async fn update_password(ctx: &AppContext, uid: ObjectId, old_password: Option<String>, new_password: String) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(voter) = ctx.voters_coll.find_one(doc! { "_id": uid.clone() }, None).await? {
        if let Some(password_hashed) = voter.password_hashed.as_ref() {
			if let Some(salt) = voter.salt.as_ref() {
				if let Some(old_password) = old_password {
					let pwrt = format!("{}{}", old_password, salt);
					if !bcrypt::verify(pwrt, password_hashed).ok().unwrap_or(false) {
						return Err(ServiceError::new_error_kind(SERVICE_NAME, "INCORRECT_PASSWORD").into());
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
				} else {
					// missing: old password
					return Err(ServiceError::new_error_kind(SERVICE_NAME, "INCORRECT_PASSWORD").into());
				}
			}
			if let Some(old_password) = old_password {
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
					return Err(ServiceError::new_error_kind(SERVICE_NAME, "INCORRECT_PASSWORD").into());
				}
			} else {
				let mut voter = voter.clone();
				let mut salt = [0u8; 16];
				OsRng.fill_bytes(&mut salt);
				let new_password_hashed = argon2::hash_encoded(new_password.as_bytes(), &salt, &Config::default())?;
				voter.salt = None;
				voter.password_hashed = Some(new_password_hashed.clone());
				ctx.voters_coll.replace_one(doc! { "_id": uid.clone() }, voter.clone(), None).await?;
				return Ok(());
			}
		} else {
			return Err(ServiceError::new_error_kind(SERVICE_NAME, "LOGIN_METHOD_NOT_SUPPORTED").into());
		}
    };
    Ok(())
}


pub async fn remove_voter(ctx: &AppContext, uid: ObjectId) -> Result<(), Box<dyn std::error::Error>> {
	if let Some(mut voter) = ctx.voters_coll.find_one(doc! { "_id": uid.clone() }, None).await? {
		voter.removed = Some(true);
		voter.email = None;
		voter.email_verified = false;
		voter.phone = None;
		voter.phone_verified = false;
		// TODO: log this event
		ctx.voters_coll.replace_one(doc! { "_id": uid.clone() }, voter.clone(), None).await?;
	}
	Ok(())
}
