use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthMode {
    Asymmetric, 
    Symmetric
}