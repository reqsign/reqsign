use std::fs;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread::sleep;

use anyhow::anyhow;
use backon::ExponentialBackoff;
use log::warn;
use quick_xml::de;
use serde::Deserialize;

use super::config::ConfigLoader;
use crate::credential::Credential;
use crate::time::parse_rfc3339;

/// CredentialLoader will load credential from different methods.
#[cfg_attr(test, derive(Debug))]
pub struct CredentialLoader {
    credential: Arc<RwLock<Option<Credential>>>,

    disable_env: bool,
    disable_profile: bool,
    #[allow(unused)]
    disable_assume_role: bool,
    disable_assume_role_with_web_identity: bool,

    client: ureq::Agent,
    config_loader: ConfigLoader,
}

impl Default for CredentialLoader {
    fn default() -> Self {
        Self {
            credential: Arc::new(Default::default()),
            disable_env: false,
            disable_profile: false,
            disable_assume_role: false,
            disable_assume_role_with_web_identity: false,
            client: ureq::Agent::new(),
            config_loader: Default::default(),
        }
    }
}

impl CredentialLoader {
    /// Disable load from env.
    pub fn with_disable_env(mut self) -> Self {
        self.disable_env = true;
        self
    }

    /// Disable load from profile.
    pub fn with_disable_profile(mut self) -> Self {
        self.disable_profile = true;
        self
    }

    /// Disable load from assume role with web identity.
    pub fn with_disable_assume_role_with_web_identity(mut self) -> Self {
        self.disable_assume_role_with_web_identity = true;
        self
    }

    /// Set Credential.
    pub fn with_credential(self, cred: Credential) -> Self {
        *self.credential.write().expect("lock poisoned") = Some(cred);
        self
    }

    /// Set config loader.
    pub fn with_config_loader(mut self, cfg: ConfigLoader) -> Self {
        self.config_loader = cfg;
        self
    }

    /// Load credential.
    pub fn load(&self) -> Option<Credential> {
        // Return cached credential if it's valid.
        match self.credential.read().expect("lock poisoned").clone() {
            Some(cred) if cred.is_valid() => return Some(cred),
            _ => (),
        }

        self.load_via_env()
            .or_else(|| self.load_via_profile())
            .or_else(|| self.load_via_assume_role_with_web_identity())
            .map(|cred| {
                let mut lock = self.credential.write().expect("lock poisoned");
                *lock = Some(cred.clone());

                cred
            })
    }

    fn load_via_env(&self) -> Option<Credential> {
        if self.disable_env {
            return None;
        }

        self.config_loader.load_via_env();

        if let (Some(ak), Some(sk)) = (
            self.config_loader.access_key_id(),
            self.config_loader.secret_access_key(),
        ) {
            let mut cred = Credential::new(&ak, &sk);
            cred.set_security_token(self.config_loader.session_token().as_deref());
            Some(cred)
        } else {
            None
        }
    }

    fn load_via_profile(&self) -> Option<Credential> {
        if self.disable_profile {
            return None;
        }

        self.config_loader.load_via_profile();

        if let (Some(ak), Some(sk)) = (
            self.config_loader.access_key_id(),
            self.config_loader.secret_access_key(),
        ) {
            let mut cred = Credential::new(&ak, &sk);
            cred.set_security_token(self.config_loader.session_token().as_deref());
            Some(cred)
        } else {
            None
        }
    }

    #[allow(unused)]
    fn load_via_assume_role(&self) -> Option<Credential> {
        todo!()
    }

    fn load_via_assume_role_with_web_identity(&self) -> Option<Credential> {
        if self.disable_assume_role_with_web_identity {
            return None;
        }

        // Based on our user reports, AWS STS may need 10s to reach consistency
        // Let's retry 4 times: 1s -> 2s -> 4s -> 8s.
        //
        // Reference: <https://github.com/datafuselabs/opendal/issues/288>
        let mut retry = ExponentialBackoff::default()
            .with_max_times(4)
            .with_jitter();

        loop {
            match self.load_via_assume_role_with_web_identity_inner() {
                Ok(v) => return v,
                Err(e) => match retry.next() {
                    Some(dur) => {
                        sleep(dur);
                        continue;
                    }
                    None => {
                        warn!("load credential via assume role with web identity failed: {e}");
                        return None;
                    }
                },
            }
        }
    }

    fn load_via_assume_role_with_web_identity_inner(&self) -> anyhow::Result<Option<Credential>> {
        let (token_file, role_arn) = match (
            self.config_loader.web_identity_token_file(),
            self.config_loader.role_arn(),
        ) {
            (Some(token_file), Some(role_arn)) => (token_file, role_arn),
            _ => return Ok(None),
        };

        let token = fs::read_to_string(&token_file)?;
        let role_session_name = self.config_loader.role_session_name();

        // Construct request to AWS STS Service.
        let url = format!("https://sts.amazonaws.com/?Action=AssumeRoleWithWebIdentity&RoleArn={role_arn}&WebIdentityToken={token}&Version=2011-06-15&RoleSessionName={role_session_name}");
        let req = self.client.get(&url).set(
            http::header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        );

        let resp = req.call()?;
        if resp.status() != http::StatusCode::OK {
            let content = resp.into_string()?;
            return Err(anyhow!("request to AWS STS Services failed: {content}"));
        }

        let resp: AssumeRoleWithWebIdentityResponse = de::from_str(&resp.into_string()?)?;
        let resp_cred = resp.result.credentials;

        let cred = Credential::new(&resp_cred.access_key_id, &resp_cred.secret_access_key)
            .with_security_token(&resp_cred.session_token)
            .with_expires_in(parse_rfc3339(&resp_cred.expiration)?);

        cred.check()?;

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: AssumeRoleWithWebIdentityResult,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityResult {
    credentials: AssumeRoleWithWebIdentityCredentials,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct AssumeRoleWithWebIdentityCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::str::FromStr;

    use anyhow::Result;
    use http::Request;
    use log::debug;
    use quick_xml::de;
    use reqwest::blocking::Client;

    use super::*;
    use crate::aws::constants::*;

    #[test]
    fn test_credential_env_loader_without_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars_unset(vec![AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY], || {
            let l = CredentialLoader::default()
                .with_disable_profile()
                .with_disable_assume_role_with_web_identity();
            let x = l.load();
            assert!(x.is_none());
        });
    }

    #[test]
    fn test_credential_env_loader_with_env() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (AWS_ACCESS_KEY_ID, Some("access_key_id")),
                (AWS_SECRET_ACCESS_KEY, Some("secret_access_key")),
            ],
            || {
                let l = CredentialLoader::default()
                    .with_disable_profile()
                    .with_disable_assume_role_with_web_identity();
                let x = l.load();
                debug!("current loader: {l:?}");

                let x = x.expect("must load succeed");
                assert_eq!("access_key_id", x.access_key());
                assert_eq!("secret_access_key", x.secret_key());
            },
        );
    }

    #[test]
    fn test_credential_profile_loader_from_config() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/not_exist",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                let l = CredentialLoader::default().with_disable_assume_role_with_web_identity();
                let x = l.load().expect("load must success");
                assert_eq!("config_access_key_id", x.access_key());
                assert_eq!("config_secret_access_key", x.secret_key());
            },
        );
    }

    #[test]
    fn test_credential_profile_loader_from_shared() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/not_exist",
                        env::current_dir()
                            .expect("load must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_credential",
                        env::current_dir()
                            .expect("load must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                let l = CredentialLoader::default().with_disable_assume_role_with_web_identity();
                let x = l.load().expect("load must success");
                assert_eq!("shared_access_key_id", x.access_key());
                assert_eq!("shared_secret_access_key", x.secret_key());
            },
        );
    }

    /// AWS_SHARED_CREDENTIALS_FILE should be taken first.
    #[test]
    fn test_credential_profile_loader_from_both() {
        let _ = env_logger::builder().is_test(true).try_init();

        temp_env::with_vars(
            vec![
                (
                    AWS_CONFIG_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_config",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
                (
                    AWS_SHARED_CREDENTIALS_FILE,
                    Some(format!(
                        "{}/testdata/services/aws/default_credential",
                        env::current_dir()
                            .expect("current_dir must exist")
                            .to_string_lossy()
                    )),
                ),
            ],
            || {
                let l = CredentialLoader::default().with_disable_assume_role_with_web_identity();
                let x = l.load().expect("load must success");
                assert_eq!("shared_access_key_id", x.access_key());
                assert_eq!("shared_secret_access_key", x.secret_key());
            },
        );
    }

    #[test]
    fn test_signer_with_web_loader() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        dotenv::from_filename(".env").ok();

        if env::var("REQSIGN_AWS_V4_TEST").is_err()
            || env::var("REQSIGN_AWS_V4_TEST").unwrap() != "on"
        {
            return Ok(());
        }

        let role_arn = env::var("REQSIGN_AWS_ROLE_ARN").expect("REQSIGN_AWS_ROLE_ARN not exist");
        let idp_url = env::var("REQSIGN_AWS_IDP_URL").expect("REQSIGN_AWS_IDP_URL not exist");
        let idp_content = base64::decode(
            env::var("REQSIGN_AWS_IDP_BODY").expect("REQSIGN_AWS_IDP_BODY not exist"),
        )?;

        let mut req = Request::new(idp_content);
        *req.method_mut() = http::Method::POST;
        *req.uri_mut() = http::Uri::from_str(&idp_url)?;
        req.headers_mut()
            .insert(http::header::CONTENT_TYPE, "application/json".parse()?);

        #[derive(Deserialize)]
        struct Token {
            access_token: String,
        }
        let token = Client::new()
            .execute(req.try_into()?)?
            .json::<Token>()?
            .access_token;

        let file_path = format!(
            "{}/testdata/services/aws/web_identity_token_file",
            env::current_dir()
                .expect("current_dir must exist")
                .to_string_lossy()
        );
        fs::write(&file_path, token)?;

        temp_env::with_vars(
            vec![
                ("AWS_ROLE_ARN", Some(&role_arn)),
                ("AWS_WEB_IDENTITY_TOKEN_FILE", Some(&file_path)),
            ],
            || {
                let l = CredentialLoader::default();
                let x = l.load().expect("load_credential must success");

                assert!(x.is_valid());
            },
        );

        Ok(())
    }

    #[test]
    fn test_parse_assume_role_with_web_identity_response() -> Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let content = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Audience>test_audience</Audience>
    <AssumedRoleUser>
      <AssumedRoleId>role_id:reqsign</AssumedRoleId>
      <Arn>arn:aws:sts::123:assumed-role/reqsign/reqsign</Arn>
    </AssumedRoleUser>
    <Provider>arn:aws:iam::123:oidc-provider/example.com/</Provider>
    <Credentials>
      <AccessKeyId>access_key_id</AccessKeyId>
      <SecretAccessKey>secret_access_key</SecretAccessKey>
      <SessionToken>session_token</SessionToken>
      <Expiration>2022-05-25T11:45:17Z</Expiration>
    </Credentials>
    <SubjectFromWebIdentityToken>subject</SubjectFromWebIdentityToken>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>b1663ad1-23ab-45e9-b465-9af30b202eba</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#;

        let resp: AssumeRoleWithWebIdentityResponse =
            de::from_str(content).expect("xml deserialize must success");

        assert_eq!(&resp.result.credentials.access_key_id, "access_key_id");
        assert_eq!(
            &resp.result.credentials.secret_access_key,
            "secret_access_key"
        );
        assert_eq!(&resp.result.credentials.session_token, "session_token");
        assert_eq!(&resp.result.credentials.expiration, "2022-05-25T11:45:17Z");

        Ok(())
    }
}
