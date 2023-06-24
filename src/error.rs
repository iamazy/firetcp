use thiserror::Error;

#[derive(Error, Debug)]
pub enum FireError {
    #[error("Errno: {0}")]
    Errno(#[from] nix::errno::Errno),
    #[error("Buffer too short")]
    BufferTooShort,
    #[error("No device found")]
    NoDeviceFound,
}

pub type FireResult<T> = std::result::Result<T, FireError>;
