use std::{fs::File, io::Read, path::Path};

use rand_core::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;
#[doc = include_str!("../README.md")]
use sha2::{Digest, Sha512};

fn xor<T: Into<Vec<u8>>>(x: T, y: &String) -> Vec<u8> {
    let x: Vec<u8> = x.into();
    let mut y = y.as_bytes().to_vec();

    let mut hasher = Sha512::new();
    hasher.update(y.clone());
    let seed: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();

    let mut rng = Hc128Rng::from_seed(seed);

    while y.len() < x.len() {
        let mut fill = [0u8; 8];
        rng.fill_bytes(fill.as_mut_slice());
        y.append(&mut Vec::from(fill));
    }

    x.into_iter().zip(y).map(|(a, b)| a ^ b).collect()
}

/// A passkey you can use to verify/store a password.
///
/// Can be a hash of a password, a plaintext password, or an encrypted password.
/// Encryption is an xor with a key, using rand::Hc128Rng to generate pseudorandom filler (seeded by the key).
/// ***Using a long, random encryption key is stongly advised!***
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Passkey {
    Hash(String),
    Plain(String),
    Encrypted(Vec<u8>),
}

impl AsRef<[u8]> for Passkey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Encrypted(ctext) => &ctext,
            Self::Hash(t) | Self::Plain(t) => t.as_bytes(),
        }
    }
}

impl Passkey {
    /// Checks against another passkey.
    ///
    /// If the key is encrypted, and `other` is not, requires a key to decrypt with.
    pub fn check(&self, other: &Passkey, key: Option<&String>) -> bool {
        if let Self::Encrypted(ctext1) = self {
            if let Self::Encrypted(ctext2) = other {
                return ctext1 == ctext2;
            }
        }

        let hash = other.hash(key);

        hash == self.hash(key)
    }

    /// Returns a Passkey::Hash of the password, using sha512.
    ///
    /// If the password is encrypted, requires a key to decrypt with.
    pub fn hash(&self, key: Option<&String>) -> Option<Passkey> {
        Some(Passkey::Hash(match self {
            Self::Hash(hash) => hash.clone(),
            Self::Plain(pass) => {
                let mut hasher = Sha512::new();
                hasher.update(pass);
                format!("{:x}", hasher.finalize())
            }
            Self::Encrypted(_) => {
                let pass = self.decrypt(key?)?;

                let mut hasher = Sha512::new();
                hasher.update(pass);
                format!("{:x}", hasher.finalize())
            }
        }))
    }

    /// Encrypts the password. Cannot encrypt a hash.
    ///
    /// Does nothing if the password is already encrypted.
    pub fn encrypt(&self, key: &String) -> Option<Passkey> {
        Some(match self {
            Self::Hash(_) => None?,
            Self::Plain(pass) => Passkey::Encrypted(xor(pass.clone(), key)),
            Self::Encrypted(_) => self.clone(),
        })
    }

    /// Encrypts the password. Cannot decrypt a hash.
    ///
    /// Does nothing if the password is already decrypted.
    pub fn decrypt(&self, key: &String) -> Option<Passkey> {
        Some(match self {
            Self::Hash(_) => None?,
            Self::Encrypted(ctext) => {
                Passkey::Plain(String::from_utf8(xor(ctext.clone(), key)).ok()?)
            }
            Self::Plain(_) => self.clone(),
        })
    }
}

/// Password data.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Data {
    location: String,
    email: Option<String>,
    username: Option<String>,
}

impl Data {
    /// Creates a Data with just a location.
    pub fn location(location: String) -> Self {
        Self {
            location,
            ..Default::default()
        }
    }

    /// Creates a Data with a location and email.
    pub fn email(location: String, email: String) -> Self {
        Self {
            location,
            email: Some(email),
            username: None,
        }
    }

    /// Creates a Data with a location and username.
    pub fn username(location: String, username: String) -> Self {
        Self {
            location,
            email: None,
            username: Some(username),
        }
    }
}

/// A Passkey with associated information (Data).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Password {
    pass: Passkey,
    data: Vec<Data>,
}

impl Password {
    /// Creates a new password.
    pub fn new(pass: Passkey) -> Self {
        Self {
            pass,
            data: Vec::new(),
        }
    }

    /// Checks against a passkey.
    ///
    /// If the key is encrypted, and `other` is not, requires a key to decrypt with.
    pub fn check(&self, other: &Passkey, key: Option<&String>) -> bool {
        self.pass.check(other, key)
    }

    /// Returns all associated emails.
    pub fn email(&self) -> Vec<String> {
        self.data
            .iter()
            .filter(|d| d.email.is_some())
            .map(|d| d.email.clone().unwrap())
            .collect()
    }

    /// Returns all associated usernames.
    pub fn username(&self) -> Vec<String> {
        self.data
            .iter()
            .filter(|d| d.username.is_some())
            .map(|d| d.username.clone().unwrap())
            .collect()
    }

    /// Returns all associated locations.
    pub fn location(&self) -> Vec<String> {
        self.data.iter().map(|d| d.location.clone()).collect()
    }

    /// Adds a location with an email.
    pub fn add_email(&mut self, location: String, email: String) {
        self.add(Data::email(location, email));
    }

    /// Adds  location with a username.
    pub fn add_username(&mut self, location: String, username: String) {
        self.add(Data::username(location, username));
    }

    /// Adds a location without a username or email.
    pub fn add_location(&mut self, location: String) {
        self.add(Data::location(location));
    }

    /// Adds a location.
    pub fn add(&mut self, data: Data) {
        self.data.push(data);
    }

    /// Removes a location.
    pub fn remove_location(&mut self, location: String) {
        self.data = self
            .data
            .clone()
            .into_iter()
            .filter(|d| d.location != location)
            .collect();
    }

    /// Removes all locations with a given email.
    pub fn remove_email(&mut self, email: String) {
        self.data = self
            .data
            .clone()
            .into_iter()
            .filter(|d| d.email != Some(email.clone()))
            .collect();
    }

    /// Removes all locations with a given username.
    pub fn remove_username(&mut self, username: String) {
        self.data = self
            .data
            .clone()
            .into_iter()
            .filter(|d| d.username != Some(username.clone()))
            .collect();
    }
}

#[derive(Debug)]
pub enum LoadPasswordsError {
    InvalidSyntax,
    FileError(std::io::Error),
}

/// A password manager.
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PassManager {
    passwords: Vec<Password>,
}

impl TryFrom<String> for PassManager {
    type Error = LoadPasswordsError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        todo!("make passwords from {value}")
    }
}

impl TryFrom<&Path> for PassManager {
    type Error = LoadPasswordsError;
    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let mut file = File::open(path).map_err(LoadPasswordsError::FileError)?;

        let mut data = String::new();
        file.read_to_string(&mut data)
            .map_err(LoadPasswordsError::FileError)?;

        data.try_into()
    }
}

impl PassManager {
    /// Creates a new manager.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn passwords(&self) -> Vec<Password> {
        self.passwords.clone()
    }

    /// Adds a password.
    ///
    /// If the password already exists, updates the password instead (unless it's encrypted).
    pub fn add_password(&mut self, mut password: Password) {
        if let Some(pass) = self
            .passwords
            .iter_mut()
            .find(|p| p.check(&password.pass, None))
        {
            pass.data.append(&mut password.data);
        } else {
            self.passwords.push(password);
        }
    }

    /// Retrieves a password by location.
    /// 
    /// If multiple passwords share a location, returns the first occurence.
    pub fn get_location(&self, location: String) -> Option<Password> {
        self.get_data(Data::location(location))
    }
    
    /// Retrieves a password by location and email.
    /// 
    /// If multiple passwords share a location and email, returns the first occurence.
    pub fn get_email(&self, location: String, email: String) -> Option<Password> {
        self.get_data(Data::email(location, email))
    }

    /// Retrieves a password by location and username.
    /// 
    /// If multiple passwords share a location and username, returns the first occurence.
    pub fn get_username(&self, location: String, username: String) -> Option<Password> {
        self.get_data(Data::username(location, username))
    }

    /// Retrieves a password by data.
    /// 
    /// Ignores empty fields in `data`.
    pub fn get_data(&self, data: Data) -> Option<Password> {
        self.passwords.iter()
            .find(|d| {
                d.location().contains(&data.location) &&
                (data.email.is_none() || d.email().contains((&data.email).as_ref().unwrap())) &&
                (data.username.is_none() || d.username().contains((&data.username).as_ref().unwrap()))
            }).cloned()
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn plain_verif() {
        let pass1 = Passkey::Plain(String::from("Hello, World! 0123456789"));
        let pass2 = Passkey::Plain(String::from("Hello, World! 0123456788"));

        let hash1 = pass1.hash(None).unwrap();
        let hash2 = pass2.hash(None).unwrap();

        assert!(pass1.check(&pass1, None));
        assert!(pass1.check(&hash1, None));

        assert!(!pass1.check(&pass2, None));
        assert!(!pass1.check(&hash2, None));

        assert!(pass2.check(&pass2, None));
        assert!(pass2.check(&hash2, None));

        assert!(!pass2.check(&pass1, None));
        assert!(!pass2.check(&hash1, None));
    }

    #[test]
    fn encrypted_verif() {
        let pass1 = Passkey::Plain(String::from("Hello, World! 0123456789"));
        let pass2 = Passkey::Plain(String::from("Hello, World! 0123456788"));

        let hash1 = pass1.hash(None).unwrap();
        let hash2 = pass2.hash(None).unwrap();

        let key1 = String::from("abc1234");
        let key2 = String::from("abc1233");

        let enc1 = pass1.encrypt(&key1).unwrap();
        let enc2 = pass2.encrypt(&key2).unwrap();

        assert_eq!(pass1, enc1.decrypt(&key1).unwrap());
        assert_eq!(pass2, enc2.decrypt(&key2).unwrap());

        assert_eq!(hash1, enc1.hash(Some(&key1)).unwrap());
        assert_eq!(hash2, enc2.hash(Some(&key2)).unwrap());

        assert!(enc1.check(&enc1, None));
        assert!(enc1.check(&pass1, Some(&key1)));
        assert!(enc1.check(&hash1, Some(&key1)));

        assert!(!enc1.check(&pass1, Some(&key2)));
        assert!(!enc1.check(&pass2, Some(&key1)));
        assert!(!enc1.check(&pass2, Some(&key2)));

        assert!(!enc1.check(&hash1, Some(&key2)));
        assert!(!enc1.check(&hash2, Some(&key1)));
        assert!(!enc1.check(&hash2, Some(&key2)));

        assert!(enc2.check(&enc2, None));
        assert!(enc2.check(&pass2, Some(&key2)));
        assert!(enc2.check(&hash2, Some(&key2)));

        assert!(!enc2.check(&pass2, Some(&key1)));
        assert!(!enc2.check(&pass1, Some(&key2)));
        assert!(!enc2.check(&pass1, Some(&key1)));

        assert!(!enc2.check(&hash2, Some(&key1)));
        assert!(!enc2.check(&hash1, Some(&key2)));
        assert!(!enc2.check(&hash1, Some(&key1)));
    }
}
