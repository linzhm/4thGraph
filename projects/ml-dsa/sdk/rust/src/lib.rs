pub use bsv_script_lab_local_sdk::{
    Config, LocalClient, Output, Payment, Recognition, Result, SigningOptions, Spend,
};

pub fn client(config: Config) -> LocalClient {
    LocalClient::new("ml-dsa", config)
}
