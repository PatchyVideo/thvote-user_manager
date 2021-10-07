
use actix_web::{App, HttpMessage, HttpRequest, HttpServer, Responder, web};
use bson::oid::ObjectId;
use actix_web::{error, http::header, http::StatusCode, HttpResponse, ResponseError};
use std::fmt::{Display, Formatter, Result as FmtResult};
use crate::{context::AppContext, legacy_login, models::ServiceError, new_login};

use super::models;

pub async fn login_email_password(ctx: web::Data<AppContext>, request: HttpRequest, body: actix_web::web::Json<models::EmailLoginInputsForExistingVoters>) -> Result<web::Json<models::LoginResults>, ServiceError> {
	let sid = request.cookie("sid").map(|f| f.to_string());
	let result = legacy_login::login_email_password(&ctx, body.email.clone(), body.password.clone(), Some(body.meta.user_ip.clone()), body.meta.additional_fingureprint.clone(), sid).await;
	match result {
		Ok(r) => {
			let vote_token = r.generate_vote_token(ctx.vote_year, &ctx.key_pair)?;
			return Ok(web::Json(models::LoginResults { vote_token: vote_token }));
		},
		Err(e) => {
			if let Some(service_error) = e.downcast_ref::<ServiceError>() {
				return Err(service_error.clone());
			} else {
				return Err(ServiceError::Unknown { detail: format!("{:?}", e) });
			}
		},
	}
}

pub async fn login_email(ctx: web::Data<AppContext>, request: HttpRequest, body: actix_web::web::Json<models::EmailLoginInputs>) -> Result<web::Json<models::LoginResults>, ServiceError> {
	let sid = request.cookie("sid").map(|f| f.to_string());
	let result = new_login::login_email(&ctx, body.email.clone(), body.verify_code.clone(), body.nickname.clone(), Some(body.meta.user_ip.clone()), body.meta.additional_fingureprint.clone(), sid).await;
	match result {
		Ok(r) => {
			let vote_token = r.generate_vote_token(ctx.vote_year, &ctx.key_pair)?;
			return Ok(web::Json(models::LoginResults { vote_token: vote_token }));
		},
		Err(e) => {
			if let Some(service_error) = e.downcast_ref::<ServiceError>() {
				return Err(service_error.clone());
			} else {
				return Err(ServiceError::Unknown { detail: format!("{:?}", e) });
			}
		},
	}
}

pub async fn login_phone(ctx: web::Data<AppContext>, request: HttpRequest, body: actix_web::web::Json<models::PhoneLoginInputs>) -> Result<web::Json<models::LoginResults>, ServiceError> {
	let sid = request.cookie("sid").map(|f| f.to_string());
	let result = new_login::login_phone(&ctx, body.phone.clone(), body.verify_code.clone(), body.nickname.clone(), Some(body.meta.user_ip.clone()), body.meta.additional_fingureprint.clone(), sid).await;
	match result {
		Ok(r) => {
			let vote_token = r.generate_vote_token(ctx.vote_year, &ctx.key_pair)?;
			return Ok(web::Json(models::LoginResults { vote_token: vote_token }));
		},
		Err(e) => {
			if let Some(service_error) = e.downcast_ref::<ServiceError>() {
				return Err(service_error.clone());
			} else {
				return Err(ServiceError::Unknown { detail: format!("{:?}", e) });
			}
		},
	}
}

pub async fn send_phone_verify_code(ctx: web::Data<AppContext>, body: actix_web::web::Json<models::SendPhoneVerifyCodeRequest>) -> Result<web::Json<models::EmptyJSON>, ServiceError> {
	let result = new_login::send_sms(&ctx, body.phone.clone(), Some(body.meta.user_ip.clone()), body.meta.additional_fingureprint.clone()).await;
	match result {
		Ok(r) => {
			return Ok(web::Json(models::EmptyJSON::new()));
		},
		Err(e) => {
			if let Some(service_error) = e.downcast_ref::<ServiceError>() {
				return Err(service_error.clone());
			} else {
				return Err(ServiceError::Unknown { detail: format!("{:?}", e) });
			}
		},
	}
}

pub async fn send_email_verify_code(ctx: web::Data<AppContext>, body: actix_web::web::Json<models::SendEmailVerifyCodeRequest>) -> Result<web::Json<models::EmptyJSON>, ServiceError> {
	let result = new_login::send_email(&ctx, body.email.clone(), Some(body.meta.user_ip.clone()), body.meta.additional_fingureprint.clone()).await;
	match result {
		Ok(r) => {
			return Ok(web::Json(models::EmptyJSON::new()));
		},
		Err(e) => {
			if let Some(service_error) = e.downcast_ref::<ServiceError>() {
				return Err(service_error.clone());
			} else {
				return Err(ServiceError::Unknown { detail: format!("{:?}", e) });
			}
		},
	}
}

