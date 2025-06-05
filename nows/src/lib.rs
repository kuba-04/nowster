use std::fs;
use std::path::PathBuf;
use nostr_sdk::hashes::hex::DisplayHex;

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
    file_name: &str,
    content: AccountFile,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = app_dir.join(file_name);
    fs::write(&file_path, content.encrypted_key)?;

    println!("Created key file: {}", file_path.display());
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
    // println!("file_data: {:?}", &file_data);
    Some(file_data.unwrap())
}
