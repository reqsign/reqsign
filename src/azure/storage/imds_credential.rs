use async_trait::async_trait;
use http::{HeaderValue, Method, Request};
use reqwest::{Client, Url};
use serde::{de::Deserializer, Deserialize};
use std::str;

const MSI_API_VERSION: &str = "2019-08-01";

/// Attempts authentication using a managed identity that has been assigned to the deployment environment.
///
/// This authentication type works in Azure VMs, App Service and Azure Functions applications, as well as the Azure Cloud Shell
///
/// Built up from docs at [https://docs.microsoft.com/azure/app-service/overview-managed-identity#using-the-rest-protocol](https://docs.microsoft.com/azure/app-service/overview-managed-identity#using-the-rest-protocol)
pub struct ImdsManagedIdentityCredential {
    endpoint: Option<String>,
    secret: Option<String>,
    object_id: Option<String>,
    client_id: Option<String>,
    msi_res_id: Option<String>,
}

impl Default for ImdsManagedIdentityCredential {
    /// Creates an instance of the `TransportOptions` with the default parameters.
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ImdsManagedIdentityCredential {
    /// Creates a new `ImdsManagedIdentityCredential` with the specified parameters.
    pub fn new() -> Self {
        Self {
            object_id: None,
            client_id: None,
            msi_res_id: None,
            secret: None,
            endpoint: None,
        }
    }

    /// Specifies the endpoint from which the identity should be retrieved.
    pub fn with_endpoint<A>(mut self, endpoint: A) -> Self
    where
        A: Into<String>,
    {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Specifies the secret associated with a user assigned managed service identity resource that should be used to retrieve the access token.
    pub fn with_secret<A>(mut self, secret: A) -> Self
    where
        A: Into<String>,
    {
        self.secret = Some(secret.into());
        self
    }

    /// Specifies the object id associated with a user assigned managed service identity resource that should be used to retrieve the access token.
    ///
    /// The values of client_id and msi_res_id are discarded, as only one id parameter may be set when getting a token.
    pub fn with_object_id<A>(mut self, object_id: A) -> Self
    where
        A: Into<String>,
    {
        self.object_id = Some(object_id.into());
        self.client_id = None;
        self.msi_res_id = None;
        self
    }

    /// Specifies the application id (client id) associated with a user assigned managed service identity resource that should be used to retrieve the access token.
    ///
    /// The values of object_id and msi_res_id are discarded, as only one id parameter may be set when getting a token.
    pub fn with_client_id<A>(mut self, client_id: A) -> Self
    where
        A: Into<String>,
    {
        self.client_id = Some(client_id.into());
        self.object_id = None;
        self.msi_res_id = None;
        self
    }

    /// Specifies the ARM resource id of the user assigned managed service identity resource that should be used to retrieve the access token.
    ///
    /// The values of object_id and client_id are discarded, as only one id parameter may be set when getting a token.
    pub fn with_identity<A>(mut self, msi_res_id: A) -> Self
    where
        A: Into<String>,
    {
        self.msi_res_id = Some(msi_res_id.into());
        self.object_id = None;
        self.client_id = None;
        self
    }

    pub async fn get_token(&self, resource: &str) -> anyhow::Result<MsiTokenResponse> {
        let msi_endpoint = self
            .endpoint
            .unwrap_or_else(|_| "http://169.254.169.254/metadata/identity/oauth2/token".to_owned());

        let mut query_items = vec![("api-version", MSI_API_VERSION), ("resource", resource)];

        match (
            self.object_id.as_ref(),
            self.client_id.as_ref(),
            self.msi_res_id.as_ref(),
        ) {
            (Some(object_id), None, None) => query_items.push(("object_id", object_id)),
            (None, Some(client_id), None) => query_items.push(("client_id", client_id)),
            (None, None, Some(msi_res_id)) => query_items.push(("msi_res_id", msi_res_id)),
            _ => (),
        }

        let url = Url::parse_with_params(&msi_endpoint, &query_items)?;
        let mut builder = Request::builder();
        builder = builder.method(Method::Get);
        builder = builder.uri(url);
        let mut req = builder.body("")?;

        req.headers_mut()
            .insert("metadata", HeaderValue::from_static("true"));

        if let Some(secret) = &self.secret {
            req.headers_mut()
                .insert("x-identity-header", HeaderValue::from_str(secret)?);
        };

        let res = Client::new().execute(req.try_into()?).await?;
        let rsp_status = res.status();
        let rsp_body = res.into_body().collect().await?;

        if !rsp_status.is_success() {
            panic!("Error getting MSI token: {}", res.text()?);
        }

        let x: MsiTokenResponse = serde_json::from_slice(&rsp_body)?;

        Ok(x)
    }
}

// NOTE: expires_on is a String version of unix epoch time, not an integer.
// https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=dotnet#rest-protocol-examples
#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
struct MsiTokenResponse {
    pub access_token: String,
    // #[serde(deserialize_with = "expires_on_string")]
    // pub expires_on: OffsetDateTime,
    pub token_type: String,
    pub resource: String,
}
