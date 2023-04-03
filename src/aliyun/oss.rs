//! Aliyun OSS Singer

use std::collections::HashSet;
use std::fmt::Write;
use std::time::Duration;

use anyhow::Result;
use http::header::AUTHORIZATION;
use http::header::CONTENT_TYPE;
use http::header::DATE;
use http::HeaderValue;
use log::debug;
use once_cell::sync::Lazy;
use percent_encoding::utf8_percent_encode;

use super::credential::Credential;
use crate::ctx::SigningContext;
use crate::ctx::SigningMethod;
use crate::hash::base64_hmac_sha1;
use crate::request::SignableRequest;
use crate::time;
use crate::time::format_http_date;
use crate::time::DateTime;

const CONTENT_MD5: &str = "content-md5";

/// Singer for Aliyun OSS.
pub struct Signer {
    bucket: String,
}

impl Signer {
    /// Create a new signer
    pub fn new(bucket: &str) -> Self {
        Self {
            bucket: bucket.to_owned(),
        }
    }

    /// Building a signing context.
    fn build(
        &self,
        req: &mut impl SignableRequest,
        method: SigningMethod,
        cred: &Credential,
    ) -> Result<SigningContext> {
        let now = time::now();
        let mut ctx = req.build()?;

        let string_to_sign = string_to_sign(&mut ctx, cred, now, method, &self.bucket)?;
        let signature =
            base64_hmac_sha1(cred.access_key_secret.as_bytes(), string_to_sign.as_bytes());

        match method {
            SigningMethod::Header => {
                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.headers.insert(AUTHORIZATION, {
                    let mut value: HeaderValue =
                        format!("OSS {}:{}", cred.access_key_id, signature).parse()?;
                    value.set_sensitive(true);

                    value
                });
            }
            SigningMethod::Query(expire) => {
                ctx.headers.insert(DATE, format_http_date(now).parse()?);
                ctx.query_push("OSSAccessKeyId", &cred.access_key_id);
                ctx.query_push(
                    "Expires",
                    (now + chrono::Duration::from_std(expire).unwrap())
                        .timestamp()
                        .to_string(),
                );
                ctx.query_push(
                    "Signature",
                    utf8_percent_encode(&signature, percent_encoding::NON_ALPHANUMERIC).to_string(),
                )
            }
        }

        Ok(ctx)
    }

    /// Signing request with header.
    pub fn sign(&self, req: &mut impl SignableRequest, cred: &Credential) -> Result<()> {
        let ctx = self.build(req, SigningMethod::Header, cred)?;

        req.apply(ctx)
    }

    /// Signing request with query.
    pub fn sign_query(
        &self,
        req: &mut impl SignableRequest,
        expire: Duration,
        cred: &Credential,
    ) -> Result<()> {
        let ctx = self.build(req, SigningMethod::Query(expire), cred)?;

        req.apply(ctx)
    }
}

/// Construct string to sign.
///
/// # Format
///
/// ```text
///   VERB + "\n"
/// + Content-MD5 + "\n"
/// + Content-Type + "\n"
/// + Date + "\n"
/// + CanonicalizedOSSHeaders
/// + CanonicalizedResource
/// ```
fn string_to_sign(
    ctx: &mut SigningContext,
    cred: &Credential,
    now: DateTime,
    method: SigningMethod,
    bucket: &str,
) -> Result<String> {
    let mut s = String::new();
    s.write_str(ctx.method.as_str())?;
    s.write_str("\n")?;
    s.write_str(ctx.header_get_or_default(&CONTENT_MD5.parse()?)?)?;
    s.write_str("\n")?;
    s.write_str(ctx.header_get_or_default(&CONTENT_TYPE)?)?;
    s.write_str("\n")?;
    match method {
        SigningMethod::Header => {
            writeln!(&mut s, "{}", format_http_date(now))?;
        }
        SigningMethod::Query(expires) => {
            writeln!(
                &mut s,
                "{}",
                (now + chrono::Duration::from_std(expires).unwrap()).timestamp()
            )?;
        }
    }

    {
        let headers = canonicalize_header(ctx, method, cred)?;
        if !headers.is_empty() {
            writeln!(&mut s, "{headers}",)?;
        }
    }
    write!(
        &mut s,
        "{}",
        canonicalize_resource(ctx, bucket, method, cred)
    )?;

    debug!("string to sign: {}", &s);
    Ok(s)
}

/// Build canonicalize header
///
/// # Reference
///
/// [Building CanonicalizedOSSHeaders](https://help.aliyun.com/document_detail/31951.html#section-w2k-sw2-xdb)
fn canonicalize_header(
    ctx: &mut SigningContext,
    method: SigningMethod,
    cred: &Credential,
) -> Result<String> {
    if method == SigningMethod::Header {
        // Insert security token
        if let Some(token) = &cred.security_token {
            ctx.headers.insert("x-oss-security-token", token.parse()?);
        }
    }

    Ok(SigningContext::header_to_string(
        ctx.header_to_vec_with_prefix("x-oss-"),
        ":",
        "\n",
    ))
}

/// Build canonicalize resource
///
/// # Reference
///
/// [Building CanonicalizedResource](https://help.aliyun.com/document_detail/31951.html#section-w2k-sw2-xdb)
fn canonicalize_resource(
    ctx: &mut SigningContext,
    bucket: &str,
    method: SigningMethod,
    cred: &Credential,
) -> String {
    if let SigningMethod::Query(_) = method {
        // Insert security token
        if let Some(token) = &cred.security_token {
            ctx.query
                .push(("security-token".to_string(), token.to_string()));
        };
    }

    let params = ctx.query_to_vec_with_filter(is_sub_resource);

    let params_str = SigningContext::query_to_string(params, "=", "&");

    if params_str.is_empty() {
        format!("/{bucket}{}", ctx.path_percent_decoded())
    } else {
        format!("/{bucket}{}?{params_str}", ctx.path_percent_decoded())
    }
}

fn is_sub_resource(v: &str) -> bool {
    SUB_RESOURCES.contains(&v)
}

/// This list is copied from <https://github.com/aliyun/aliyun-oss-go-sdk/blob/master/oss/conn.go>
static SUB_RESOURCES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "acl",
        "uploads",
        "location",
        "cors",
        "logging",
        "website",
        "referer",
        "lifecycle",
        "delete",
        "append",
        "tagging",
        "objectMeta",
        "uploadId",
        "partNumber",
        "security-token",
        "position",
        "img",
        "style",
        "styleName",
        "replication",
        "replicationProgress",
        "replicationLocation",
        "cname",
        "bucketInfo",
        "comp",
        "qos",
        "live",
        "status",
        "vod",
        "startTime",
        "endTime",
        "symlink",
        "x-oss-process",
        "response-content-type",
        "x-oss-traffic-limit",
        "response-content-language",
        "response-expires",
        "response-cache-control",
        "response-content-disposition",
        "response-content-encoding",
        "udf",
        "udfName",
        "udfImage",
        "udfId",
        "udfImageDesc",
        "udfApplication",
        "comp",
        "udfApplicationLog",
        "restore",
        "callback",
        "callback-var",
        "qosInfo",
        "policy",
        "stat",
        "encryption",
        "versions",
        "versioning",
        "versionId",
        "requestPayment",
        "x-oss-request-payer",
        "sequential",
        "inventory",
        "inventoryId",
        "continuation-token",
        "asyncFetch",
        "worm",
        "wormId",
        "wormExtend",
        "withHashContext",
        "x-oss-enable-md5",
        "x-oss-enable-sha1",
        "x-oss-enable-sha256",
        "x-oss-hash-ctx",
        "x-oss-md5-ctx",
        "transferAcceleration",
        "regionList",
        "cloudboxes",
        "x-oss-ac-source-ip",
        "x-oss-ac-subnet-mask",
        "x-oss-ac-vpc-id",
        "x-oss-ac-forward-allow",
        "metaQuery",
    ])
});
