//! Installation-wide credentials shared by API and worker. The database
//! contains authenticated ciphertext and a display suffix only.
use crate::{config::Config, db::Db};
use anyhow::{anyhow, Context, Result};
use ring::{aead, rand as secure};
use secure::SecureRandom;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

pub(crate) struct Provider {
    pub id: &'static str,
    label: &'static str,
    applications: &'static [&'static str],
}

const PROVIDERS: &[Provider] = &[
    Provider {
        id: "censys",
        label: "Censys",
        applications: &["Subfinder", "Asset Discovery", "Reverse IP"],
    },
    Provider {
        id: "certspotter",
        label: "Cert Spotter",
        applications: &["Subfinder", "Certificate Transparency"],
    },
    Provider {
        id: "securitytrails",
        label: "SecurityTrails",
        applications: &["Subfinder"],
    },
    Provider {
        id: "shodan",
        label: "Shodan",
        applications: &["Subfinder"],
    },
    Provider {
        id: "virustotal",
        label: "VirusTotal",
        applications: &["Subfinder"],
    },
];

pub(crate) fn provider(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|provider| provider.id == id)
}

pub(crate) fn valid_key(key: &str) -> bool {
    (8..=2048).contains(&key.len())
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte))
}

pub(crate) fn status(db: &Db, config: &Config) -> Result<Vec<Value>> {
    let suffixes = db.provider_key_suffixes()?;
    Ok(PROVIDERS
        .iter()
        .map(|provider| {
            let suffix = suffixes.get(provider.id);
            let from_server = match provider.id {
                "censys" => config.censys_integration().configured,
                "certspotter" => config.certspotter_token.is_some(),
                _ => false,
            };
            json!({
                "id": provider.id,
                "name": provider.label,
                "applications": provider.applications,
                "configured": suffix.is_some() || from_server,
                "last_four": suffix,
            })
        })
        .collect())
}

pub(crate) fn has_saved_censys_pat(db: &Db) -> Result<bool> {
    Ok(db.provider_key_suffixes()?.contains_key("censys"))
}

pub(crate) fn subfinder_keys(
    db: &Db,
    config: &Config,
) -> Result<BTreeMap<&'static str, Vec<String>>> {
    let mut keys = BTreeMap::new();
    for provider in PROVIDERS {
        let value = read_key(db, config, provider.id)?.or_else(|| match provider.id {
            "censys" => config.censys_pat.clone(),
            "certspotter" => config.certspotter_token.clone(),
            _ => None,
        });
        if let Some(mut key) = value {
            if provider.id == "censys" {
                if let Some(org) = &config.censys_organization_id {
                    key.push(':');
                    key.push_str(org);
                }
            }
            keys.insert(provider.id, vec![key]);
        }
    }
    Ok(keys)
}

const NONCE_BYTES: usize = 12;
type MasterKey = [u8; 32];

pub(crate) fn save_key(
    db: &Db,
    config: &Config,
    actor: &str,
    provider: &Provider,
    secret: &str,
) -> Result<()> {
    let path = config.data_dir.join("providers.key");
    let key = cipher(&load_or_create_key(&path)?)?;
    // Either of two concurrent writers can publish a credential first.
    #[cfg(unix)]
    fs::File::open(&config.data_dir)?.sync_all()?;
    let random = secure::SystemRandom::new();
    let mut nonce = [0u8; NONCE_BYTES];
    random
        .fill(&mut nonce)
        .map_err(|_| anyhow!("cannot generate credential nonce"))?;
    let mut ciphertext = secret.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(provider.id),
        &mut ciphertext,
    )
    .map_err(|_| anyhow!("cannot encrypt provider credential"))?;
    let mut record = nonce.to_vec();
    record.extend(ciphertext);
    db.save_provider_credential(actor, provider.id, &record, &secret[secret.len() - 4..])
}

pub(crate) fn read_key(db: &Db, config: &Config, provider: &str) -> Result<Option<String>> {
    let Some(mut record) = db.provider_ciphertext(provider)? else {
        return Ok(None);
    };
    let path = config.data_dir.join("providers.key");
    let master =
        read_master_key(&path).context("cannot read installation provider encryption key")?;
    let (nonce, ciphertext) = record
        .split_at_mut_checked(NONCE_BYTES)
        .context("invalid encrypted provider credential")?;
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| anyhow!("invalid provider credential nonce"))?;
    let secret = cipher(&master)?
        .open_in_place(nonce, aead::Aad::from(provider), ciphertext)
        .map_err(|_| anyhow!("cannot decrypt provider credential with this installation key"))?;
    let secret = std::str::from_utf8(secret).map_err(|_| anyhow!("invalid provider credential"))?;
    Ok(Some(secret.to_owned()))
}

fn cipher(key: &MasterKey) -> Result<aead::LessSafeKey> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| anyhow!("invalid installation provider encryption key"))?;
    Ok(aead::LessSafeKey::new(key))
}

fn read_master_key(path: &Path) -> io::Result<MasterKey> {
    let key = fs::read(path)?;
    key.try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid provider key length"))
}

fn load_or_create_key(path: &Path) -> Result<MasterKey> {
    match read_master_key(path) {
        Ok(key) => return Ok(key),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut key = [0u8; 32];
    secure::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| anyhow!("cannot generate installation provider encryption key"))?;
    let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    let published = file
        .write_all(&key)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::hard_link(&tmp, path));
    let _ = fs::remove_file(tmp);
    match published {
        Ok(()) => {
            #[cfg(unix)]
            fs::File::open(path.parent().context("provider key path has no parent")?)?
                .sync_all()?;
            Ok(key)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(read_master_key(path)?),
        Err(error) => Err(error.into()),
    }
}
