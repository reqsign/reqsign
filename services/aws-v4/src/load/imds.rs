use crate::Credential;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::Method;
use reqsign_core::time::{now, parse_rfc3339, DateTime};
use reqsign_core::{Context, Load};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct IMDSv2Loader {
    token: Arc<Mutex<(String, DateTime)>>,
}

impl IMDSv2Loader {
    async fn load_ec2_metadata_token(&self, ctx: &Context) -> Result<String> {
        {
            let (token, expires_in) = self.token.lock().expect("lock poisoned").clone();
            if expires_in > now() {
                return Ok(token);
            }
        }

        let url = "http://169.254.169.254/latest/api/token";
        let req = http::Request::builder()
            .uri(url)
            .method(Method::PUT)
            .header(CONTENT_LENGTH, "0")
            // 21600s (6h) is recommended by AWS.
            .header("x-aws-ec2-metadata-token-ttl-seconds", "21600")
            .body(Bytes::new())?;
        let mut resp = ctx.http_send_as_string(req).await?;

        if resp.status() != http::StatusCode::OK {
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {}",
                resp.body()
            ));
        }
        let ec2_token = resp.into_body();
        // Set expires_in to 10 minutes to enforce re-read.
        let expires_in = now() + chrono::TimeDelta::try_seconds(21600).expect("in bounds")
            - chrono::TimeDelta::try_seconds(600).expect("in bounds");

        {
            *self.token.lock().expect("lock poisoned") = (ec2_token.clone(), expires_in);
        }

        Ok(ec2_token)
    }
}

#[async_trait]
impl Load for IMDSv2Loader {
    type Key = Credential;

    async fn load(&self, ctx: &Context) -> Result<Option<Self::Key>> {
        let token = self.load_ec2_metadata_token(ctx).await?;

        // List all credentials that node has.
        let url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let req = http::Request::builder()
            .uri(url)
            .method(Method::GET)
            // 21600s (6h) is recommended by AWS.
            .header("x-aws-ec2-metadata-token", &token)
            .body(Bytes::new())?;
        let mut resp = ctx.http_send_as_string(req).await?;
        if resp.status() != http::StatusCode::OK {
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {}",
                resp.body()
            ));
        }

        let profile_name = resp.into_body();

        // Get the credentials via role_name.
        let url = format!(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/{profile_name}"
        );
        let req = http::Request::builder()
            .uri(url)
            .method(Method::GET)
            // 21600s (6h) is recommended by AWS.
            .header("x-aws-ec2-metadata-token", &token)
            .body(Bytes::new())?;

        let mut resp = ctx.http_send_as_string(req).await?;
        if resp.status() != http::StatusCode::OK {
            return Err(anyhow!(
                "request to AWS EC2 Metadata Services failed: {}",
                resp.body()
            ));
        }

        let content = resp.into_body();
        let resp: Ec2MetadataIamSecurityCredentials = serde_json::from_str(&content)?;
        if resp.code == "AssumeRoleUnauthorizedAccess" {
            return Err(anyhow!(
                "Incorrect IMDS/IAM configuration: [{}] {}. \
                        Hint: Does this role have a trust relationship with EC2?",
                resp.code
                resp.message
            ));
        }
        if resp.code != "Success" {
            return Err(anyhow!(
                "Error retrieving credentials from IMDS: {} {}",
                resp.code,
                resp.message
            ));
        }

        let cred = Credential {
            access_key_id: resp.access_key_id,
            secret_access_key: resp.secret_access_key,
            session_token: Some(resp.token),
            expires_in: Some(parse_rfc3339(&resp.expiration)?),
        };

        Ok(Some(cred))
    }
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct Ec2MetadataIamSecurityCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,

    code: String,
    message: String,
}
