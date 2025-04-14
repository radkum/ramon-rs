use thiserror::Error;

#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),

    #[error("SendMsgError: {0}")]
    SendMsgError(String),

    #[error("UnknownEvent")]
    UnknownEvent,
}
