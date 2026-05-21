// Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
//
// Author: JINLIANG XU
// Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
//

//! Client helpers for calling OAN services.

use reqwest::Url;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(#[from] url::ParseError),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Clone, Debug)]
pub struct OanClient {
    base_url: Url,
    http: reqwest::Client,
}

impl OanClient {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, ClientError> {
        Ok(Self {
            base_url: Url::parse(base_url.as_ref())?,
            http: reqwest::Client::new(),
        })
    }

    pub fn endpoint(&self, path: &str) -> Result<Url, ClientError> {
        Ok(self.base_url.join(path.trim_start_matches('/'))?)
    }

    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        Ok(self
            .http
            .get(self.endpoint(path)?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn post_json<B, T>(&self, path: &str, body: &B) -> Result<T, ClientError>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        Ok(self
            .http
            .post(self.endpoint(path)?)
            .json(body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_endpoint_paths() {
        let client = OanClient::new("http://localhost:8000").unwrap();
        assert_eq!(
            client.endpoint("/health").unwrap().as_str(),
            "http://localhost:8000/health"
        );
    }
}

