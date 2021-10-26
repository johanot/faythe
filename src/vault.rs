use vaultrs::client::VaultClient;
use vaultrs::client::VaultClientSettingsBuilder;
use vaultrs::auth::approle;
//use vaultrs::sys::wrapping;
//use std::fs;
use crate::config::VaultConfig;
use envfile::EnvFile;
use crate::log;

use vaultrs::kv2;
use vaultrs::client::Client;
use std::collections::HashMap;

#[derive(Debug)]
pub enum VaultError {
    MissingConfigKey(String),
    Client(vaultrs::error::ClientError),
    IO(std::io::Error),
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultAppRoleSecretID {
    secret_id: String,
    secret_id_accessor: String,
    secret_id_ttl: u64,
}

pub async fn authenticate(
    config: &VaultConfig,
) -> Result<VaultClient, VaultError> {
    let envfile = EnvFile::new(&config.app_role_env_file).map_err(|inner| VaultError::IO(inner))?;
    
    // Token unwrapping .. not needed, because provisioned app role secrets by our module are unwrapped, currently
    /*
    let wrapping_token = fs::read_to_string().map_err(|inner| VaultError::IO(inner))?;
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(&config.addr)
            .token(wrapping_token)
            .build()
            .unwrap(),
    ).map_err(|inner| VaultError::Client(inner))?;
    let unwrapped_resp: VaultAppRoleSecretID =
        wrapping::unwrap(&client, None).await.map_err(|inner| VaultError::Client(inner))?;

    let secret_id = unwrapped_resp.secret_id;
    */

    let role_id = envfile.get("ROLE_ID").ok_or(VaultError::MissingConfigKey("ROLE_ID".to_string()))?;
    let secret_id = envfile.get("SECRET_ID").ok_or(VaultError::MissingConfigKey("SECRET_ID".to_string()))?;

    let mut client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(&config.addr)
            .build()
            .unwrap(),
    ).map_err(|inner| VaultError::Client(inner))?;

    // Authentication
    let app_role_login_response = approle::login(
            &client,
            "approle",
            &role_id,
            &secret_id,
        )
        .await.map_err(|inner| VaultError::Client(inner))?;

    client.set_token(&app_role_login_response.client_token);
    Ok(client)
}

pub async fn read(
    client: &VaultClient,
    config: &VaultConfig,
    key: &str,
) -> Result<HashMap<String, String>, VaultError> {
    let key = format!("{prefix}/{key}", prefix=&config.kv_prefix, key=&key);
    log::info(&format!("fetching key: {} from Vault", &key));
    kv2::read(client, &config.kv_mount, &key)
        .await.map_err(|inner| VaultError::Client(inner))
}
