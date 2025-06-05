use std::{io};
use std::str::FromStr;
use std::time::Duration;
use nostr_sdk::{Client, Filter, Keys};
use nostr_sdk::async_utility::tokio;
use encryption::{decrypt_from_string, encrypt_to_string};
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

        let encrypted_key = read_key("/nows/storage/", &key_file)
            .expect("Could not read master password");
        let decrypted_key = decrypt_from_string(
            &encrypted_key,
            password,
        ).expect("Decryption failed");

    //     nostr
    //     let keys = Keys::parse(decrypted_key.as_str());
    //     let keys = Keys::from_str(&decrypted_key);
    //     let client = Client::new(keys.unwrap());
    //
    //     let _ = client.add_relay("wss://relay.damus.io").await;
    //     client.connect().await;
    //
    //     for event in client.fetch_events(Filter::new(), Duration::new(5, 0)).await.unwrap() {
    //         println!("{:?}", event.content);
    //     }


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
        let encrypted_payload = encrypt_to_string(
            priv_key.as_bytes(),
            Some(master_password.as_bytes())
        ).expect("Encryption failed");

        println!("Encryption successful.");

        println!("---");
        println!("Step 2. Storing encrypted data...");
        let storage = get_or_create_app_dir("nows/storage").expect("Failed to create app dir");
        let _ = create_file(
            storage,
            pubkey.to_string().as_str(),
            AccountFile::new(&encrypted_payload.as_str())
        );
    }
}