//! Local Script Lab client. The signer callback stays in the caller's process.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

pub struct Config {
    pub python: PathBuf,
    pub bridge: PathBuf,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Recognition {
    pub template: String,
    pub owner_hash160: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub value_sats: String,
    pub script: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningOptions {
    pub funding: String,
    pub index: u32,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sighash: Option<u8>,
    pub chronicle_active: bool,
    pub compress_otda: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_identifier: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct Spend {
    #[serde(flatten)]
    pub options: SigningOptions,
    pub transaction: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Payment {
    #[serde(flatten)]
    pub options: SigningOptions,
    pub outputs: Vec<Output>,
    pub fee_sats: String,
}

pub struct LocalClient {
    project: &'static str,
    config: Config,
}

impl LocalClient {
    pub fn new(project: &'static str, config: Config) -> Self {
        Self { project, config }
    }

    fn call<T: DeserializeOwned>(
        &self,
        operation: &str,
        request: &Value,
        signing: Option<(&[String], &[u8])>,
    ) -> Result<T> {
        let mut message = json!({
            "protocol": 1, "project": self.project, "operation": operation, "request": request
        });
        if let Some((arguments, signature)) = signing {
            message["arguments"] = json!(arguments);
            message["signature"] = json!(hex::encode(signature));
        }
        let input = serde_json::to_vec(&message)?;
        let mut child = Command::new(&self.config.python)
            .arg(&self.config.bridge)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let write = child.stdin.take().expect("piped stdin").write_all(&input);
        let response = child.wait_with_output()?;
        if !response.status.success() {
            return Err(
                io::Error::other(format!("local SDK bridge exited: {}", response.status)).into(),
            );
        }
        write?;
        let mut reply: Value = serde_json::from_slice(&response.stdout)?;
        if reply["ok"].as_bool() != Some(true) {
            return Err(io::Error::other(
                reply["error"]
                    .as_str()
                    .unwrap_or("invalid SDK bridge response"),
            )
            .into());
        }
        Ok(serde_json::from_value(reply["result"].take())?)
    }

    pub fn lock(&self, public_key: &str, profile: Option<&str>) -> Result<String> {
        let mut request = json!({"publicKey": public_key});
        if let Some(profile) = profile {
            request["profile"] = json!(profile);
        }
        self.call("lock", &request, None)
    }

    pub fn recognize(&self, script: &str, public_key: Option<&str>) -> Result<Option<Recognition>> {
        let mut request = json!({"script": script});
        if let Some(key) = public_key {
            request["publicKey"] = json!(key);
        }
        self.call("recognize", &request, None)
    }

    pub fn lock_for_owner(&self, owner_hash160: &str) -> Result<String> {
        self.call("lockOwner", &json!({"ownerHash160": owner_hash160}), None)
    }

    fn sign(
        &self,
        options: impl Serialize,
        signer: impl FnOnce(&[Vec<u8>]) -> Result<Vec<u8>>,
    ) -> Result<String> {
        let snapshot = serde_json::to_value(options)?;
        let arguments: Vec<String> = self.call("prepare", &snapshot, None)?;
        let decoded = arguments
            .iter()
            .map(hex::decode)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let signature = signer(&decoded)?;
        self.call("finish", &snapshot, Some((&arguments, &signature)))
    }

    pub fn sign_spend(
        &self,
        request: Spend,
        signer: impl FnOnce(&[Vec<u8>]) -> Result<Vec<u8>>,
    ) -> Result<String> {
        self.sign(request, signer)
    }

    pub fn sign_payment(
        &self,
        request: Payment,
        signer: impl FnOnce(&[Vec<u8>]) -> Result<Vec<u8>>,
    ) -> Result<String> {
        self.sign(request, signer)
    }
}
