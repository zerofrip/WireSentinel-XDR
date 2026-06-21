use thiserror::Error;

#[derive(Debug, Error)]
pub enum XdrError {
    #[error("edr error: {0}")]
    Edr(String),
    #[error("ndr error: {0}")]
    Ndr(String),
    #[error("itdr error: {0}")]
    Itdr(String),
    #[error("hunting error: {0}")]
    Hunting(String),
    #[error("detection error: {0}")]
    Detection(String),
    #[error("incident error: {0}")]
    Incident(String),
    #[error("case error: {0}")]
    Case(String),
    #[error("soar error: {0}")]
    Soar(String),
    #[error("attack graph error: {0}")]
    AttackGraph(String),
    #[error("mitre error: {0}")]
    Mitre(String),
    #[error("response error: {0}")]
    Response(String),
    #[error("security error: {0}")]
    Security(String),
    #[error("{0}")]
    Other(String),
}

pub type XdrResult<T> = std::result::Result<T, XdrError>;
