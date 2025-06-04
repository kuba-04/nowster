use std::{fs, io};
use std::path::PathBuf;
use nostr_sdk::{Client, Keys};
use nostr_sdk::hashes::hex::{Case, DisplayHex};
use encryption::encrypt_data;

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
        Some(master_password.as_bytes())
    ).expect("Encryption failed");

    println!("Encryption successful.");
    println!(
        "  Ciphertext length: {}",
        encrypted_payload.ciphertext.len()
    );

    println!("---");
    println!("Step 2. Storing encrypted data...");
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
