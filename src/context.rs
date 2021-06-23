use jwt_simple::prelude::ES256kKeyPair;
use mongodb::{Collection, Database};

use crate::models::Voter;


#[derive(Clone)]
pub struct AppContext {
    //pub key_pair: ES256kKeyPair
    pub db: Database,
    pub voters_coll: Collection<Voter>
}
