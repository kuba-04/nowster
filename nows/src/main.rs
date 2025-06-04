use std::{io};
use std::str::FromStr;
use nostr_sdk::{Client, Keys};
use nostr_sdk::async_utility::tokio;
use nostr_sdk::hashes::hex::{Case, DisplayHex};
use encryption::{decrypt_from_string, encrypt_data};
use nows::{create_file, find_first_file, get_or_create_app_dir, read_key, AccountFile};

#[tokio::main]
async fn main() {
    let app_storage_dir = dirs::data_local_dir()
        .expect("Could not find local data directory")
        .to_string_lossy()
        .to_string();
    if let Some(key_file) = find_first_file(&format!("{app_storage_dir}/nows/storage/")) {
        // println!("Account already exists: {key_file}");
        // println!("At the moment nowster supports only one user on local machine.");
        // //todo: impl this feature below
        // // println!("Run `nows --remove <your_pubkey>` to delete the account");

        // positive path:
        // 0. ask for password if required (Optional)
        // 1. decrypt the key
        // 2. load latest 5 notes
        // 3. hit SPACE to load another 5

        // // Decrypt the user's password (string)
        println!("Type your password if required");
        let mut typed_password = String::new();
        let _ = io::stdin().read_line(&mut typed_password);
        typed_password = typed_password.trim().to_string();
        let mut password = None;
        if !typed_password.is_empty() {
            password = Some(typed_password);
        }

        // println!("file to read: {:?}", &key_file);

        let encrypted_key = read_key("/nows/storage/", &key_file)
            .expect("Could not read master password");
        let decrypted_key = decrypt_from_string(
            &encrypted_key,
            password,
        ).expect("Decryption failed");

        println!("Decryption successful.");
        println!("---");

    //     nostr
    //     let keys = Keys::parse(decrypted_key.as_str());
        let keys = Keys::from_str(&decrypted_key);
        let client = Client::new(keys.unwrap());

        let _ = client.add_relay("wss://relay.damus.io").await;
        client.connect().await;


    } else {
        // negative path:
        // 1. ask user about his key and password
        // 2. encrypt and save
        // 3. go to positive path

        println!("GM! what's your private key?");
        print!("Priv key: ");
        let mut priv_key = String::new();
        let _ = io::stdin().read_line(&mut priv_key);
        priv_key = priv_key.trim().to_string();
        let keys = Keys::parse(priv_key.as_str());
        let pubkey = keys.expect("Failed to parse keys").public_key;

        println!("You can use password for additional security of key derivation.\nIf you add it, \
    then everytime you run the program, you have to type this password. For no password, press ENTER");
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
        create_file(
            storage,
            pubkey.to_string().as_str(),
            AccountFile::new(encrypted_payload.ciphertext.to_hex_string(Case::Lower).as_str()))
            .expect("Failed to create key file");
    }




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