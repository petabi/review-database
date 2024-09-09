//! All the models stored in the database.

use std::sync::LazyLock;

use native_db::Models;

pub(crate) static MODELS: LazyLock<Models> = LazyLock::new(|| models().expect("valid model"));

pub type TrustedDomain = v1::TrustedDomain;

pub(crate) fn models() -> anyhow::Result<Models> {
    let mut models = Models::new();
    models.define::<TrustedDomain>()?;
    Ok(models)
}

pub(crate) mod v1 {
    use native_db::{native_db, ToKey};
    use native_model::{native_model, Model};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
    #[native_model(id = 1, version = 1)]
    #[native_db]
    pub struct TrustedDomain {
        #[primary_key]
        pub name: String,
        pub remarks: String,
    }
}

mod tests {
    #[test]
    fn validate_models() {
        assert!(super::models().is_ok());
    }
}
