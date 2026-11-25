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

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Prevout {
    pub txid: String,
    pub vout: u32,
    #[serde(flatten)]
    pub output: Output,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_hash160: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_sats: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecognizeRequest {
    pub script: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_sats: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WalletRecognition {
    #[serde(flatten)]
    pub lock: Recognition,
    pub project: String,
    pub public_key: Option<String>,
    pub target_template: Option<String>,
    pub target_script_sha256: Option<String>,
    pub target_tx_out_hash256: Option<String>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct WalletSigningOptions {
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sighash: Option<u8>,
    pub chronicle_active: bool,
    pub compress_otda: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_path: Option<PathBuf>,
    pub sign_message: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletPayment {
    pub prevout: Prevout,
    pub outputs: Vec<Output>,
    pub fee_sats: String,
    #[serde(flatten)]
    pub options: WalletSigningOptions,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletInput {
    pub prevout: Prevout,
    pub transaction: String,
    pub input_index: u32,
    #[serde(flatten)]
    pub options: WalletSigningOptions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Activation {
    pub prevout: Prevout,
    pub transaction: String,
    pub input_index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sighash: Option<u8>,
    pub chronicle_active: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningRequest {
    pub algorithm: String,
    pub payload_kind: String,
    pub signature_format: String,
    pub sighash: u8,
    #[serde(skip)]
    pub payload: Vec<u8>,
    #[serde(skip)]
    pub user_id: Option<Vec<u8>>,
}

pub struct WalletClient {
    bridge: LocalClient,
    template: Option<String>,
}

impl WalletClient {
    pub fn new(project: &'static str, config: Config, template: Option<String>) -> Self {
        Self {
            bridge: LocalClient::new(project, config),
            template,
        }
    }

    pub fn prevout_from_funding(&self, funding: &str, vout: u32) -> Result<Prevout> {
        self.bridge.call(
            "prevoutFromFunding",
            &json!({"funding": funding, "vout": vout}),
            None,
        )
    }

    pub fn create_lock(&self, options: LockRequest) -> Result<String> {
        let mut request = serde_json::to_value(options)?;
        request["template"] = json!(self.template);
        self.bridge.call("createLock", &request, None)
    }

    pub fn recognize(&self, request: RecognizeRequest) -> Result<Option<WalletRecognition>> {
        self.bridge
            .call("recognizeLock", &serde_json::to_value(request)?, None)
    }

    fn sign(
        &self,
        request: impl Serialize,
        signer: impl FnOnce(SigningRequest) -> Result<Vec<u8>>,
    ) -> Result<String> {
        #[derive(Deserialize)]
        struct Prepared {
            #[serde(flatten)]
            request: SigningRequest,
            arguments: Vec<String>,
        }

        let snapshot = serde_json::to_value(request)?;
        let Prepared {
            mut request,
            arguments,
        } = self.bridge.call("prepareWallet", &snapshot, None)?;
        match arguments.as_slice() {
            [payload, user_id] => {
                request.payload = hex::decode(payload)?;
                request.user_id = Some(hex::decode(user_id)?);
            }
            [payload] => request.payload = hex::decode(payload)?,
            _ => return Err(io::Error::other("invalid signing request arguments").into()),
        }
        let signature = signer(request)?;
        self.bridge
            .call("finishWallet", &snapshot, Some((&arguments, &signature)))
    }

    pub fn sign_payment(
        &self,
        request: WalletPayment,
        signer: impl FnOnce(SigningRequest) -> Result<Vec<u8>>,
    ) -> Result<String> {
        self.sign(request, signer)
    }

    pub fn sign_input(
        &self,
        request: WalletInput,
        signer: impl FnOnce(SigningRequest) -> Result<Vec<u8>>,
    ) -> Result<String> {
        self.sign(request, signer)
    }

    pub fn activate(&self, request: Activation) -> Result<String> {
        self.bridge
            .call("activate", &serde_json::to_value(request)?, None)
    }
}
