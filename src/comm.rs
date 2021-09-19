
#[cfg(debug_assertions)]
pub const REDIS_ADDRESS: &'static str = "redis://192.168.0.54:6379";

#[cfg(not(debug_assertions))]
pub const REDIS_ADDRESS: &'static str = "redis://redis:6379";

#[cfg(debug_assertions)]
pub const SERVICE_SMS_ADDRESS: &'static str = "http://127.0.0.1:5010";

#[cfg(not(debug_assertions))]
pub const SERVICE_SMS_ADDRESS: &'static str = "http://sms-service";
