use sha2::{Digest, Sha512};
use rand_core::{SeedableRng, RngCore};
use rand_hc::Hc128Rng;

fn xor<T: Into<Vec<u8>>>(x: T, y: &String) -> Vec<u8> {
    let x: Vec<u8> = x.into();
    let mut y = y.as_bytes().to_vec();

    let mut hasher = Sha512::new();
    hasher.update(y.clone());
    let seed: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();

    let mut rng = Hc128Rng::from_seed(seed);

    let mut fill = Vec::with_capacity(x.len() - y.len());

    rng.fill_bytes(fill.as_mut_slice());
    y.append(&mut fill);

    x.into_iter().zip(y).map(|(a, b)| a ^ b).collect()
}

/// A passkey you can use to verify/store a password.
/// 
/// Can be a hash of a password, a plaintext password, or an encrypted password.
/// Encryption is a simple xor with a key, using rand::Hc128Rng to generate random filler.
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
            Self::Hash(t) |
            Self::Plain(t) => t.as_bytes(),
        }
    }
}

impl Passkey {
    /// Checks against another key.
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

    pub fn encrypt(&self, key: &String) -> Option<Passkey> {
        Some(match self {
            Self::Hash(_) => None?,
            Self::Plain(pass) => Passkey::Encrypted(xor(pass.clone(), key)),
            Self::Encrypted(_) => self.clone(),
        })
    }

    pub fn decrypt(&self, key: &String) -> Option<Passkey> {
        Some(match self {
            Self::Hash(_) => None?,
            Self::Encrypted(ctext) => Passkey::Plain(String::from_utf8(xor(ctext.clone(), key)).ok()?),
            Self::Plain(_) => self.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Data {
    Email(String),
    Username(String),
    Location(String),
}

impl Data {
    pub fn is_email(&self) -> bool {
        if let Self::Email(_) = self {
            true
        } else {
            false
        }
    }

    pub fn is_username(&self) -> bool {
        if let Self::Email(_) = self {
            true
        } else {
            false
        }
    }

    pub fn is_location(&self) -> bool {
        if let Self::Email(_) = self {
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Password {
    pass: Passkey,
    data: Vec<Data>,
}

impl Password {
    pub fn new(pass: Passkey) -> Self {
        Self { pass, data: Vec::new() }
    }

    pub fn check(&self, other: &Passkey, key: Option<&String>) -> bool {
        self.pass.check(other, key)
    }

    pub fn email(&self) -> Vec<Data> {
        self.data
            .iter()
            .filter(|d| d.is_email())
            .map(|d| d.clone())
            .collect()
    }

    pub fn username(&self) -> Vec<Data> {
        self.data
            .iter()
            .filter(|d| d.is_username())
            .map(|d| d.clone())
            .collect()
    }

    pub fn location(&self) -> Vec<Data> {
        self.data
            .iter()
            .filter(|d| d.is_location())
            .map(|d| d.clone())
            .collect()
    }

    pub fn add_email(&mut self, email: String) {
        self.add(Data::Email(email));
    }

    pub fn add_username(&mut self, email: String) {
        self.add(Data::Username(email));
    }

    pub fn add_location(&mut self, email: String) {
        self.add(Data::Location(email));
    }

    pub fn add(&mut self, data: Data) {
        self.data.push(data);
    }

    pub fn remove_email(&mut self, email: String) {
        self.remove(Data::Email(email));
    }

    pub fn remove_username(&mut self, username: String) {
        self.remove(Data::Username(username));
    }

    pub fn remove_location(&mut self, location: String) {
        self.remove(Data::Location(location));
    }

    pub fn remove(&mut self, data: Data) {
        self.data = self.data.clone().into_iter()
            .filter(|e| e != &data)
            .collect();
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

        let key1 = String::from("abc123");
        let key2 = String::from("abc122");

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