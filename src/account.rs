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
    password: SaltedPassword,
    pub role: Role,
    pub name: String,
    pub department: String,
    creation_time: DateTime<Utc>,
    last_signin_time: Option<DateTime<Utc>>,
    pub allow_access_from: Option<Vec<IpAddr>>,
    pub max_parallel_sessions: Option<u32>,
    password_hash_algorithm: PasswordHashAlgorithm,
}

impl Account {
    const DEFAULT_HASH_ALGORITHM: PasswordHashAlgorithm = PasswordHashAlgorithm::Argon2id;

    /// Creates a new `Account` with the given information
    ///
    /// # Errors
    ///
    /// Returns an error if account creation fails.
    pub fn new(
        username: &str,
        password: &str,
        role: Role,
        name: String,
        department: String,
        allow_access_from: Option<Vec<IpAddr>>,
        max_parallel_sessions: Option<u32>,
    ) -> Result<Self> {
        let password =
            SaltedPassword::new_with_hash_algorithm(password, &Self::DEFAULT_HASH_ALGORITHM)?;
        Ok(Self {
            username: username.to_string(),
            password,
            role,
            name,
            department,
            creation_time: Utc::now(),
            last_signin_time: None,
            allow_access_from,
            max_parallel_sessions,
            password_hash_algorithm: Self::DEFAULT_HASH_ALGORITHM,
        })
    }

    /// Update `Account::password` with the given password using
    /// `Account::DEFAULT_HASH_ALGORITHM`.
    ///
    /// # Errors
    ///
    /// Returns an error if the salt for password cannot be generated.
    pub fn update_password(&mut self, password: &str) -> Result<()> {
        self.password =
            SaltedPassword::new_with_hash_algorithm(password, &Self::DEFAULT_HASH_ALGORITHM)?;
        self.password_hash_algorithm = Self::DEFAULT_HASH_ALGORITHM;
        Ok(())
    }

    #[must_use]
    pub fn verify_password(&self, provided: &str) -> bool {
        self.password.is_match(provided)
    }

    #[must_use]
    pub fn creation_time(&self) -> DateTime<Utc> {
        self.creation_time
    }

    pub fn update_last_signin_time(&mut self) {
        self.last_signin_time = Some(Utc::now());
    }

    #[must_use]
    pub fn last_signin_time(&self) -> Option<DateTime<Utc>> {
        self.last_signin_time
    }
}

#[derive(Default, Debug, Deserialize, Serialize, PartialEq)]
enum PasswordHashAlgorithm {
    #[default]
    Pbkdf2HmacSha512 = 0,
    Argon2id = 1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[repr(u32)]
enum HashAlgorithm {
    Sha512 = 0,
    Argon2id,
}

#[derive(Clone, Deserialize, Serialize)]
struct SaltedPassword {
    salt: Vec<u8>,
    hash: Vec<u8>,
    algorithm: HashAlgorithm,
    iterations: NonZeroU32,
}

impl SaltedPassword {
    /// Creates a new `SaltedPassword` with the given password and
    /// password hash algorithm to be used.
    ///
    /// # Errors
    ///
    /// Returns an error if the salt cannot be generated.
    fn new_with_hash_algorithm(
        password: &str,
        hash_algorithm: &PasswordHashAlgorithm,
    ) -> Result<Self> {
        match hash_algorithm {
            PasswordHashAlgorithm::Pbkdf2HmacSha512 => Self::with_pbkdf2(password),
            PasswordHashAlgorithm::Argon2id => Self::with_argon2id(password),
        }
    }

    /// Creates a new `SaltedPassword` with the given password.
    ///
    /// # Errors
    ///
    /// Returns an error if the salt cannot be generated.
    fn with_pbkdf2(password: &str) -> Result<Self> {
        // The recommended iteration count for PBKDF2-HMAC-SHA512 is 210,000
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        const ITERATIONS: u32 = 210_000;

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
    fn with_argon2id(password: &str) -> Result<Self> {
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
    fn is_match(&self, password: &str) -> bool {
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
        let pbkdf2 = SaltedPassword::with_pbkdf2(password).unwrap();
        assert!(pbkdf2.is_match(password));
    }

    #[test]
    fn argon2id_test() {
        let password = "password";
        let argon2id = SaltedPassword::with_argon2id(password).unwrap();
        assert!(argon2id.is_match(password));
    }

    #[test]
    fn account_password() {
        let account = Account::new(
            "test",
            "password",
            Role::SecurityAdministrator,
            String::new(),
            String::new(),
            None,
            None,
        );
        assert!(account.is_ok());

        let account = account.unwrap();
        assert_eq!(
            account.password_hash_algorithm,
            Account::DEFAULT_HASH_ALGORITHM
        );
        let password =
            SaltedPassword::new_with_hash_algorithm("password", &Account::DEFAULT_HASH_ALGORITHM)
                .unwrap();
        assert_eq!(account.password.algorithm, password.algorithm);
    }

    #[test]
    fn account_passowrd_update() {
        let mut account = Account {
            username: "test".to_string(),
            password: SaltedPassword::new_with_hash_algorithm(
                "password",
                &PasswordHashAlgorithm::Pbkdf2HmacSha512,
            )
            .unwrap(),
            role: Role::SecurityAdministrator,
            department: String::new(),
            name: String::new(),
            creation_time: Utc::now(),
            last_signin_time: None,
            allow_access_from: None,
            max_parallel_sessions: None,
            password_hash_algorithm: PasswordHashAlgorithm::Pbkdf2HmacSha512,
        };
        assert!(account.verify_password("password"));
        assert!(!account.verify_password("updated"));

        assert!(account.update_password("updated").is_ok());

        assert!(!account.verify_password("password"));
        assert!(account.verify_password("updated"));
        assert_eq!(
            account.password_hash_algorithm,
            Account::DEFAULT_HASH_ALGORITHM
        )
    }
}
