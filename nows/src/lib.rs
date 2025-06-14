use encryption::{decrypt_from_string, encrypt_to_string};
use nostr::{derive_pubkey, run_nostr};
use std::path::PathBuf;
use std::{fs, io};

pub async fn run() {
    println!("----NowStr----");
    println!();
    println!("Instructions:");
    println!("- for more hit Enter");
    println!("- for refresh(up) hit 'r'");
    println!("- for quit hit 'q'");
    println!();

    let app_storage_dir = dirs::data_local_dir()
        .expect("Could not find local data directory")
        .to_string_lossy()
        .to_string();

    let key_file_name = find_first_file(&format!("{app_storage_dir}/nows/storage/"));

    if let Some(pubkey) = key_file_name.as_ref() {
        let priv_key = obtain_key_from_mode(pubkey);

        run_nostr(priv_key, pubkey.to_string()).await;
    } else {
        println!("GM! what's your private key?");
        let mut priv_key = String::new();
        let _ = io::stdin().read_line(&mut priv_key);
        priv_key = priv_key.trim().to_string();

        println!("---");
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
        let pubkey = derive_pubkey(&priv_key);
        let _ = create_file(
            storage,
            pubkey.clone(),
            AccountFile::new(&encrypted_payload.as_str())
        );
        println!("Press ENTER to load events. For 'write' mode, type 'w' and return");
        let mut mode = String::new();
        let _ = io::stdin().read_line(&mut mode);
        mode = mode.trim().to_lowercase();

        let pk = if mode.eq("w") {
            Some(priv_key)
        } else {
            None
        };

        run_nostr(pk, pubkey).await;
    }
}

fn obtain_key_from_mode(file_name: &String) -> Option<String> {
    println!("Press ENTER to load events. For 'write' mode, type 'w' and return");
    let mut mode = String::new();
    let _ = io::stdin().read_line(&mut mode);
    mode = mode.trim().to_lowercase();

    if mode.eq("w") {
        Some(decrypt_key(file_name))
    } else {
        None
    }
}

fn decrypt_key(key_file: &String) -> String {
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
    decrypt_from_string(
        &encrypted_key,
        password,
    ).expect("Decryption failed")
}

pub fn get_or_create_app_dir(dir_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let app_dir = dirs::data_local_dir()
        .map(|pb| pb.join(dir_name))
        .ok_or("Could not determine local data directory")?;

    // Create directory if it doesn't exist
    fs::create_dir_all(&app_dir)?;

    Ok(app_dir)
}

pub fn create_file(
    app_dir: PathBuf,
    file_name: String,
    content: AccountFile,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = app_dir.join(file_name);
    fs::write(&file_path, content.encrypted_key)?;
    Ok(())
}

pub struct AccountFile {
    encrypted_key: String,
}

impl AccountFile {
    pub fn new(encrypted_key: &str) -> Self {
        AccountFile { encrypted_key: encrypted_key.to_string() }
    }
}

// pub fn file_already_exists(pubkey: &PublicKey) -> bool {
//     fs::exists(&format!("nows/storage/{}", pubkey)).unwrap_or(false)
// }

pub fn find_first_file(dir_path: &str) -> Option<String> {
    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries {
            if let Ok(entry) = entry {
                if entry.file_type().ok()?.is_file() {
                    return entry.file_name().to_string_lossy().to_string().into();
                }
            }
        }
    }
    None
}

pub fn read_key(dir_path: &str, file_name: &str) -> Option<String> {
    let app_dir = dirs::data_local_dir().unwrap().to_string_lossy().to_string();
    let file_data = fs::read_to_string(&format!("{app_dir}{dir_path}{file_name}"));
    Some(file_data.unwrap())
}
