use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload as AeadPayload}, Key as ChaChaKey, XChaCha20Poly1305, XNonce,
};
use nostr_sdk::{Client, Keys};
use scrypt;
use std::io::Write;
use std::path::PathBuf;
use std::{fs, io};
use nostr_sdk::hashes::hex::{Case, DisplayHex};

const KEY_SIZE: usize = 32; // For XChaCha20Poly1305 derived key
const NONCE_SIZE: usize = 24; // For XChaCha20 nonce
const SALT_SIZE: usize = 32; // Salt length for scrypt

// Scrypt parameters
const SCRYPT_LOG_N: u8 = 15; // N = 2^log_n. 15 => N=32768. Adjust for security/performance.
const SCRYPT_R: u32 = 8; // Scrypt 'r' parameter (memory factor)
const SCRYPT_P: u32 = 1; // Scrypt 'p' parameter (parallelization factor)

// todo: store and reuse the salt
// WARNING: In a real application, always use a unique, randomly generated salt
// for each encryption and store it with the ciphertext.
const HARDCODED_SALT: [u8; SALT_SIZE] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeySecurity {
    Low = 0,
    Medium = 1,
    High = 2,
}

impl KeySecurity {
    /// Tries to convert a u8 value back to KeySecurity.
    #[allow(dead_code)] // Potentially useful for deserialization
    pub fn from_u8(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(KeySecurity::Low),
            1 => Ok(KeySecurity::Medium),
            2 => Ok(KeySecurity::High),
            _ => Err(Error::InvalidKeySecurityValue(value)),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    ScryptError(ScryptDerivationError),
    CipherError(chacha20poly1305::aead::Error),
    FromUtf8Error(std::string::FromUtf8Error),
    InvalidKeySecurityValue(u8),
    InvalidSecretKeyData(String), // For errors during SecretKey reconstruction
}

/// Specific errors from scrypt.
#[derive(Debug)]
pub enum ScryptDerivationError {
    InvalidParams(scrypt::errors::InvalidParams),
    InvalidOutputLen(scrypt::errors::InvalidOutputLen),
}

// --- Trait Implementations for Error ---
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ScryptError(err) => match err {
                ScryptDerivationError::InvalidParams(e) => {
                    write!(f, "Scrypt KDF parameter error: {}", e)
                }
                ScryptDerivationError::InvalidOutputLen(e) => {
                    write!(f, "Scrypt KDF output length error: {}", e)
                }
            },
            Error::CipherError(_) => write!(
                f,
                "Cipher operation error (e.g., decryption/authentication failed)"
            ),
            Error::FromUtf8Error(e) => write!(f, "UTF-8 conversion error: {}", e),
            Error::InvalidKeySecurityValue(v) => {
                write!(f, "Invalid u8 value for KeySecurity enum: {}", v)
            }
            Error::InvalidSecretKeyData(s) => {
                write!(f, "Invalid data for SecretKey reconstruction: {}", s)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::ScryptError(err) => match err {
                ScryptDerivationError::InvalidParams(e) => Some(e),
                ScryptDerivationError::InvalidOutputLen(e) => Some(e),
            },
            Error::CipherError(_) => None,
            Error::FromUtf8Error(e) => Some(e),
            Error::InvalidKeySecurityValue(_) | Error::InvalidSecretKeyData(_) => None,
        }
    }
}

// From trait implementations for error variants
impl From<scrypt::errors::InvalidParams> for Error {
    fn from(e: scrypt::errors::InvalidParams) -> Self {
        Error::ScryptError(ScryptDerivationError::InvalidParams(e))
    }
}
impl From<scrypt::errors::InvalidOutputLen> for Error {
    fn from(e: scrypt::errors::InvalidOutputLen) -> Self {
        Error::ScryptError(ScryptDerivationError::InvalidOutputLen(e))
    }
}
impl From<chacha20poly1305::aead::Error> for Error {
    fn from(e: chacha20poly1305::aead::Error) -> Self {
        Error::CipherError(e)
    }
}
impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::FromUtf8Error(e)
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub salt: [u8; SALT_SIZE],     // Salt used for key derivation
    pub nonce: [u8; NONCE_SIZE],   // Nonce used for encryption
    pub log_n: u8,                 // Scrypt log_n parameter used
    pub key_security: KeySecurity, // AAD
}

// user has option to use master password or not
fn derive_key<P>(password: Option<P>, salt: &[u8; SALT_SIZE], log_n: u8) -> Result<[u8; KEY_SIZE], Error>
where
    P: AsRef<[u8]>,
{
    let key_len_nz = core::num::NonZeroUsize::new(KEY_SIZE)
        .expect("KEY_SIZE must be non-zero for scrypt params");
    let params = scrypt::Params::new(log_n, SCRYPT_R, SCRYPT_P, key_len_nz.get())?;

    let mut key = [0u8; KEY_SIZE];
    if password.is_some() {
        scrypt::scrypt(password.unwrap().as_ref(), salt, &params, &mut key)?;
    } else {
        scrypt::scrypt("".as_bytes(), salt, &params, &mut key)?;
    }
    Ok(key)
}

/// Encrypts plaintext data using a master password.
pub fn encrypt_data<P>(
    plaintext_data: &[u8],
    master_password: Option<P>,
    key_security: KeySecurity,
) -> Result<EncryptedPayload, Error>
where
    P: AsRef<[u8]>,
{
    let salt = HARDCODED_SALT; // Using hardcoded salt
    let log_n = SCRYPT_LOG_N; // Using configured scrypt cost

    // STEP 1: KEY DERIVATION
    let derived_key_array: [u8; KEY_SIZE] = derive_key(master_password, &salt, log_n)?;
    let chacha_key = ChaChaKey::from_slice(&derived_key_array);

    // STEP 2: CIPHER INITIALIZATION
    let cipher = XChaCha20Poly1305::new(chacha_key);

    // STEP 3: NONCE GENERATION
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    // OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_obj = XNonce::from_slice(&nonce_bytes);

    // STEP 4: PAYLOAD CONSTRUCTION (for encryption)
    let aad = [key_security as u8];
    let aead_payload = AeadPayload {
        msg: plaintext_data,
        aad: &aad,
    };

    // STEP 5: ENCRYPTION
    let ciphertext = cipher.encrypt(nonce_obj, aead_payload)?;

    Ok(EncryptedPayload {
        ciphertext,
        salt,
        nonce: nonce_bytes,
        log_n,
        key_security,
    })
}

/// Decrypts an `EncryptedPayload` to recover the original plaintext data as bytes.
pub fn decrypt_data<P>(
    encrypted_payload: &EncryptedPayload,
    master_password: Option<P>,
) -> Result<Vec<u8>, Error>
where
    P: AsRef<[u8]>,
{
    // STEP 1: KEY DERIVATION
    let derived_key_array: [u8; KEY_SIZE] = derive_key(
        master_password,
        &encrypted_payload.salt,
        encrypted_payload.log_n,
    )?;
    let chacha_key = ChaChaKey::from_slice(&derived_key_array);

    // STEP 2: CIPHER INITIALIZATION
    let cipher = XChaCha20Poly1305::new(chacha_key);

    // STEP 3: PAYLOAD CONSTRUCTION (for decryption)
    let aad = [encrypted_payload.key_security as u8];
    let aead_payload = AeadPayload {
        msg: &encrypted_payload.ciphertext,
        aad: &aad,
    };
    let nonce_obj = XNonce::from_slice(&encrypted_payload.nonce);

    // STEP 4: DECRYPTION
    let decrypted_bytes = cipher.decrypt(nonce_obj, aead_payload)?;

    Ok(decrypted_bytes)
}

/// Convenience function to decrypt data and convert it to a String.
pub fn decrypt_password_string<P>(
    encrypted_payload: &EncryptedPayload,
    master_password: Option<P>,
) -> Result<String, Error>
where
    P: AsRef<[u8]>,
{
    let decrypted_bytes = decrypt_data(encrypted_payload, master_password)?;
    String::from_utf8(decrypted_bytes).map_err(Error::from)
}

// --- SecretKey specific logic (analogous to the snippet) ---

/// A minimal representation of a secret key (e.g., for ECC).
#[derive(Clone)]
pub struct SecretKey([u8; 32]); // Typically 32 bytes for curves like secp256k1

impl SecretKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, String> {
        // Returns String error for simplicity
        if bytes.len() == KEY_SIZE {
            // Assuming SecretKey is also KEY_SIZE
            let mut arr = [0u8; KEY_SIZE];
            arr.copy_from_slice(bytes);
            // In a real scenario, add cryptographic validation:
            // - e.g., ensure key is not zero, and less than the curve order for ECC keys.
            Ok(SecretKey(arr))
        } else {
            Err(format!(
                "Invalid key length: expected {}, got {}",
                KEY_SIZE,
                bytes.len()
            ))
        }
    }

    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey([REDACTED {} bytes])", self.0.len())
    }
}

/// Encrypts a `SecretKey` object.
#[allow(dead_code)] // This is an example function
pub fn encrypt_secret_key<P>(
    secret_key: &SecretKey,
    master_password: Option<P>,
    key_security: KeySecurity,
) -> Result<EncryptedPayload, Error>
where
    P: AsRef<[u8]>,
{
    encrypt_data(secret_key.as_bytes(), master_password, key_security)
}

/// Decrypts data and attempts to reconstruct a `SecretKey`.
/// This is a more direct analogue to the `to_secret_key` function in your snippet.
#[allow(dead_code)] // This is an example function
pub fn to_secret_key_equivalent<P>(
    encrypted_payload: &EncryptedPayload,
    master_password: Option<P>,
) -> Result<SecretKey, Error>
where
    P: AsRef<[u8]>,
{
    let decrypted_bytes = decrypt_data(encrypted_payload, master_password)?;
    SecretKey::from_slice(&decrypted_bytes).map_err(|e_str| Error::InvalidSecretKeyData(e_str))
}

fn main() {
    // let keys: Keys = Keys::parse("".trim()).unwrap();
    // let client = Client::new(keys);
    //
    // client.add_relay()
    // io::stdout().flush()?;

    println!("GM! what's your private key?");
    print!("Priv key: ");
    let mut priv_key = String::new();
    let _ = io::stdin().read_line(&mut priv_key);
    priv_key = priv_key.trim().to_string();

    println!("You can use password for additional security of key derivation.\nIf you add it, \
    then everytime you run the program, you have to type this password also. For no password, press ENTER");
    let mut master_password = String::new();
    let _ = io::stdin().read_line(&mut master_password);
    master_password = master_password.trim().to_string();

    println!("---");

    // // Encrypt the user's password
    println!("Step 1. Encrypting password string...");
    let encrypted_payload = encrypt_data(
        priv_key.as_bytes(),
        Some(master_password.as_bytes()),
        KeySecurity::High,
    ).expect("Encryption failed");

    println!("Encryption successful.");
    println!(
        "  Ciphertext length: {}",
        encrypted_payload.ciphertext.len()
    );

    println!("---");
    println!("Step 2. Storing encrypted data...");
    // get_or_create_app_dir("nows").expect("Failed to get app dir");
    let storage = get_or_create_app_dir("nows/storage").expect("Failed to create app dir");
    let keys = Keys::parse(priv_key.as_str());
    let pubkey = keys.expect("Failed to parse keys").public_key;
    create_file(
        storage,
        pubkey.to_string().as_str(),
        AccountFile { encrypted_key: encrypted_payload.ciphertext.to_hex_string(Case::Lower) })
        .expect("Failed to create key file");

    // // Decrypt the user's password (string)
    // println!("Decrypting password string with correct master password...");
    // let decrypted_password_string = decrypt_password_string(
    //     &encrypted_payload,
    //     master_password_for_derivation.as_bytes(),
    // )
    // .expect("Decryption failed");
    //
    // println!("Decryption successful.");
    // println!("Decrypted string: \"{}\"", decrypted_password_string);
    // assert_eq!(user_password_to_encrypt, decrypted_password_string);
    // println!("---");
    //
    // // Test decryption failure with wrong master password
    // println!("Attempting decryption with WRONG master password...");
    // let wrong_master_password = "IncorrectMasterPassword";
    // match decrypt_password_string(&encrypted_payload, wrong_master_password.as_bytes()) {
    //     Ok(_) => panic!("DECRYPTION SUCCEEDED WITH WRONG MASTER PASSWORD!"),
    //     Err(e) => {
    //         println!("Decryption failed as expected: {}", e);
    //         assert!(matches!(e, Error::CipherError(_)));
    //     }
    // }
    // println!("---");
    //
    // // Test
    // println!("Testing SecretKey encryption/decryption...");
    // let mut sk_bytes = [0u8; 32];
    // rand::thread_rng().fill_bytes(&mut sk_bytes);
    // let original_secret_key = SecretKey::from_slice(&sk_bytes).unwrap();
    // println!("Original SecretKey: {:?}", original_secret_key);
    //
    // let sk_master_password = "AnotherMasterPasswordForSK";
    // let encrypted_sk_payload = encrypt_secret_key(
    //     &original_secret_key,
    //     sk_master_password.as_bytes(),
    //     KeySecurity::Medium,
    // )
    // .expect("SecretKey encryption failed");
    // println!("Encrypted SecretKey payload created.");
    //
    // let decrypted_secret_key =
    //     to_secret_key_equivalent(&encrypted_sk_payload, sk_master_password.as_bytes())
    //         .expect("SecretKey decryption failed");
    // println!("Decrypted SecretKey: {:?}", decrypted_secret_key);
    // assert_eq!(
    //     original_secret_key.as_bytes(),
    //     decrypted_secret_key.as_bytes()
    // );
    // println!("SecretKey encryption/decryption successful!");
    // println!("---");
    //
    // println!("All tests passed!");
}

fn get_or_create_app_dir(dir_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let app_dir = dirs::data_local_dir()
        .map(|pb| pb.join(dir_name))
        .ok_or("Could not determine local data directory")?;

    // Create directory if it doesn't exist
    fs::create_dir_all(&app_dir)?;

    Ok(app_dir)
}

fn create_file(
    app_dir: PathBuf,
    file_name: &str,
    content: AccountFile,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = app_dir.join(file_name);
    fs::write(&file_path, content.encrypted_key)?;

    println!("Created key file: {}", file_path.display());
    Ok(())
}

struct AccountFile {
    encrypted_key: String,
}
