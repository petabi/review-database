use anyhow::Result;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Utc};
use ring::{
    digest, pbkdf2,
    rand::{self, SecureRandom},
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, num::NonZeroU32};
use strum_macros::{Display, EnumString};

/// Possible role types of `Account`.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq, Deserialize, Serialize, EnumString)]
pub enum Role {
    #[strum(serialize = "System Administrator")]
    SystemAdministrator,
    #[strum(serialize = "Security Administrator")]
    SecurityAdministrator,
    #[strum(serialize = "Security Manager")]
    SecurityManager,
    #[strum(serialize = "Security Monitor")]
    SecurityMonitor,
}

#[derive(Deserialize, Serialize)]
pub struct Account {
    pub username: String,
    pub password: SaltedPassword,
    pub role: Role,
    pub name: String,
    pub department: String,
    pub creation_time: DateTime<Utc>,
    pub last_signin_time: Option<DateTime<Utc>>,
    pub allow_access_from: Option<Vec<IpAddr>>,
    pub max_parallel_sessions: Option<u32>,
    pub password_hash_algorithm: PasswordHashAlgorithm,
}

#[derive(Default, Deserialize, Serialize)]
pub enum PasswordHashAlgorithm {
    #[default]
    Pbkdf2HmacSha512 = 0,
    Argon2id = 1,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[repr(u32)]
pub enum HashAlgorithm {
    Sha512 = 0,
    Argon2id,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SaltedPassword {
    salt: Vec<u8>,
    hash: Vec<u8>,
    algorithm: HashAlgorithm,
    iterations: NonZeroU32,
}

impl SaltedPassword {
    /// Creates a new `SaltedPassword` with the given password.
    ///
    /// # Errors
    ///
    /// Returns an error if the salt cannot be generated.
    pub fn new(password: &str) -> Result<Self> {
        const ITERATIONS: u32 = 100_000;

        let iterations = NonZeroU32::new(ITERATIONS).expect("valid u32");
        let rng = rand::SystemRandom::new();
        let mut salt = vec![0_u8; digest::SHA512_OUTPUT_LEN];
        rng.fill(&mut salt)?;
        let mut hash = vec![0_u8; digest::SHA512_OUTPUT_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512,
            iterations,
            &salt,
            password.as_bytes(),
            &mut hash,
        );
        Ok(Self {
            salt,
            hash,
            algorithm: HashAlgorithm::Sha512,
            iterations,
        })
    }

    /// Creates a new `SaltedPassword`with argon2id from the given password.
    ///
    /// # Errors
    ///
    /// Returns an error if it fails to compute a password hash from the given
    /// password and salt value.
    pub fn with_argon2id(password: &str) -> Result<Self> {
        let salt: SaltString = SaltString::generate(&mut OsRng);

        // The default values of the `Argon2` struct are the followings:
        // algorithm: argon2id, version number = 19, memory size = 19456, number of iterations = 2, degree of parallelism = 1
        // This is one of the recommended configuration settings in the OWASP guidelines.
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

        Ok(Self {
            salt: vec![], // not used in argon2
            hash: password_hash.as_bytes().to_vec(),
            algorithm: HashAlgorithm::Argon2id,
            iterations: NonZeroU32::new(1).expect("non zero u32"), // not used in argon2
        })
    }

    #[must_use]
    pub fn is_match(&self, password: &str) -> bool {
        match self.algorithm {
            HashAlgorithm::Sha512 => pbkdf2::verify(
                pbkdf2::PBKDF2_HMAC_SHA512,
                self.iterations,
                &self.salt,
                password.as_bytes(),
                &self.hash,
            )
            .is_ok(),
            HashAlgorithm::Argon2id => {
                let hash = String::from_utf8_lossy(&self.hash);
                match PasswordHash::new(&hash) {
                    Ok(parsed_hash) => Argon2::default()
                        .verify_password(password.as_bytes(), &parsed_hash)
                        .is_ok(),
                    Err(e) => {
                        tracing::error!("Failed to parse the password hash: {hash}, reason: {e:?}");
                        false
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_test() {
        let password = "password";
        let pbkdf2 = SaltedPassword::new(password).unwrap();
        assert!(pbkdf2.is_match(password));
    }

    #[test]
    fn argon2id_test() {
        let password = "password";
        let argon2id = SaltedPassword::with_argon2id(password).unwrap();
        assert!(argon2id.is_match(password));
    }
}
