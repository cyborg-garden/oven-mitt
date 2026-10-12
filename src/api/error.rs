//! The error model (PRD §7). Every failure is one of a closed set of codes
//! with a fixed human message. Messages never carry roots, patterns,
//! storage paths, targets, credential material or hidden names (SI-6); the
//! only variable parts allowed are a destination name or a handle, both of
//! which the caller already knows.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::export::ExportError;
use crate::store::StoreError;

/// Closed set of error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Code {
    InvalidRequest,
    ProtocolUnsupported,
    VaultNotFound,
    NotFound,
    DestinationNotFound,
    DestinationKindMismatch,
    CredentialRequired,
    CredentialInvalid,
    CredentialNotPermitted,
    TargetNotAllowed,
    PathEscape,
    FilenameInvalid,
    Exists,
    TooLarge,
    Integrity,
    LabelInvalid,
    TooMany,
    Aborted,
    Storage,
    Internal,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::ProtocolUnsupported => "PROTOCOL_UNSUPPORTED",
            Self::VaultNotFound => "VAULT_NOT_FOUND",
            Self::NotFound => "NOT_FOUND",
            Self::DestinationNotFound => "DESTINATION_NOT_FOUND",
            Self::DestinationKindMismatch => "DESTINATION_KIND_MISMATCH",
            Self::CredentialRequired => "CREDENTIAL_REQUIRED",
            Self::CredentialInvalid => "CREDENTIAL_INVALID",
            Self::CredentialNotPermitted => "CREDENTIAL_NOT_PERMITTED",
            Self::TargetNotAllowed => "TARGET_NOT_ALLOWED",
            Self::PathEscape => "PATH_ESCAPE",
            Self::FilenameInvalid => "FILENAME_INVALID",
            Self::Exists => "EXISTS",
            Self::TooLarge => "TOO_LARGE",
            Self::Integrity => "INTEGRITY",
            Self::LabelInvalid => "LABEL_INVALID",
            Self::TooMany => "TOO_MANY",
            Self::Aborted => "ABORTED",
            Self::Storage => "STORAGE",
            Self::Internal => "INTERNAL",
        }
    }

    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest
            | Self::ProtocolUnsupported
            | Self::FilenameInvalid
            | Self::LabelInvalid
            | Self::Aborted => StatusCode::BAD_REQUEST,
            Self::VaultNotFound | Self::NotFound | Self::DestinationNotFound => {
                StatusCode::NOT_FOUND
            }
            Self::DestinationKindMismatch | Self::Exists => StatusCode::CONFLICT,
            Self::CredentialRequired | Self::CredentialInvalid => StatusCode::UNAUTHORIZED,
            Self::CredentialNotPermitted | Self::TargetNotAllowed | Self::PathEscape => {
                StatusCode::FORBIDDEN
            }
            Self::TooLarge | Self::TooMany => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Integrity => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Storage => StatusCode::INSUFFICIENT_STORAGE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Is this a refusal (audited) rather than a transport/internal error?
    pub fn is_refusal(self) -> bool {
        !matches!(
            self,
            Self::TooMany | Self::Aborted | Self::Storage | Self::Internal
        )
    }

    /// The fixed human message. No variable content.
    fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "the request is malformed or the route does not exist",
            Self::ProtocolUnsupported => {
                "missing or unsupported X-Ovenmitt-Protocol header; this daemon speaks protocol 1"
            }
            Self::VaultNotFound => "no such vault",
            Self::NotFound => "no such object",
            Self::DestinationNotFound => "no such destination in this object's vault",
            Self::DestinationKindMismatch => "destination kind does not allow this operation",
            Self::CredentialRequired => "resolve requires a consumer credential",
            Self::CredentialInvalid => "credential is unknown, malformed or revoked",
            Self::CredentialNotPermitted => "credential is not scoped to this object's vault",
            Self::TargetNotAllowed => "target is not permitted for this destination",
            Self::PathEscape => "export target is not inside the destination root",
            Self::FilenameInvalid => {
                "filename is invalid: letters, digits, `. _ -` and spaces, starting with a letter or digit, no `..`, at most 255 characters"
            }
            Self::Exists => "a file with that name already exists at the destination",
            Self::TooLarge => "object exceeds the configured size limit",
            Self::Integrity => "client-supplied sha256 does not match the body",
            Self::LabelInvalid => "labels: at most 16, each 1-256 bytes, no control characters",
            Self::TooMany => "too many objects to list in one response",
            Self::Aborted => "request body ended before the operation completed",
            Self::Storage => "storage failure",
            Self::Internal => "internal error",
        }
    }
}

/// An API error: a code plus, optionally, the one variable the message may
/// mention (a destination name or a handle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: Code,
    pub about: Option<String>,
    /// Status override: `INVALID_REQUEST` is 404 for an unknown route.
    pub status: Option<StatusCode>,
}

impl ApiError {
    pub fn new(code: Code) -> Self {
        Self {
            code,
            about: None,
            status: None,
        }
    }

    /// `INVALID_REQUEST` with a 404 status: no such route.
    pub fn no_route() -> Self {
        Self {
            code: Code::InvalidRequest,
            about: None,
            status: Some(StatusCode::NOT_FOUND),
        }
    }

    /// Attach a destination name or handle to the message.
    #[must_use]
    pub fn about(mut self, s: impl Into<String>) -> Self {
        self.about = Some(s.into());
        self
    }

    pub fn is_refusal(&self) -> bool {
        self.code.is_refusal()
    }

    fn full_message(&self) -> String {
        match &self.about {
            Some(a) => format!("{} ({a})", self.code.message()),
            None => self.code.message().to_owned(),
        }
    }
}

impl From<Code> for ApiError {
    fn from(code: Code) -> Self {
        Self::new(code)
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorInner<'a>,
}

#[derive(Serialize)]
struct ErrorInner<'a> {
    code: &'a str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorInner {
                code: self.code.as_str(),
                message: self.full_message(),
            },
        };
        let status = self.status.unwrap_or_else(|| self.code.status());
        (status, axum::Json(body)).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound | StoreError::Expired(_) => Code::NotFound.into(),
            StoreError::VaultNotFound => Code::VaultNotFound.into(),
            StoreError::TooLarge => Code::TooLarge.into(),
            StoreError::IntegrityMismatch => Code::Integrity.into(),
            StoreError::LabelInvalid(_) => Code::LabelInvalid.into(),
            StoreError::NameInvalid(_) | StoreError::MimeInvalid(_) => Code::InvalidRequest.into(),
            StoreError::Corrupt { .. } | StoreError::Startup(_) | StoreError::Key(_) => {
                Code::Internal.into()
            }
            StoreError::Crypto(_) => Code::Internal.into(),
            StoreError::Io(_) => Code::Storage.into(),
        }
    }
}

impl From<ExportError> for ApiError {
    fn from(e: ExportError) -> Self {
        match e {
            ExportError::FilenameInvalid => Code::FilenameInvalid.into(),
            ExportError::PathEscape => Code::PathEscape.into(),
            ExportError::Exists => Code::Exists.into(),
            ExportError::Store(s) => s.into(),
            ExportError::Io(_) => Code::Storage.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_fixed_and_codes_round_trip() {
        for code in [
            Code::InvalidRequest,
            Code::ProtocolUnsupported,
            Code::VaultNotFound,
            Code::NotFound,
            Code::DestinationNotFound,
            Code::DestinationKindMismatch,
            Code::CredentialRequired,
            Code::CredentialInvalid,
            Code::CredentialNotPermitted,
            Code::TargetNotAllowed,
            Code::PathEscape,
            Code::FilenameInvalid,
            Code::Exists,
            Code::TooLarge,
            Code::Integrity,
            Code::LabelInvalid,
            Code::TooMany,
            Code::Aborted,
            Code::Storage,
            Code::Internal,
        ] {
            let s = serde_json::to_string(&code).unwrap_or_default();
            assert_eq!(s, format!("\"{}\"", code.as_str()));
            assert!(!code.message().is_empty());
        }
        assert!(Code::NotFound.is_refusal());
        assert!(!Code::Storage.is_refusal());
        let e = ApiError::new(Code::TargetNotAllowed).about("team-chat");
        assert_eq!(
            e.full_message(),
            "target is not permitted for this destination (team-chat)"
        );
    }
}
