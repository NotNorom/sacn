use sacn::error::ReceiveError;

#[derive(Debug, thiserror::Error)]
pub enum ExampleError {
    #[error(transparent)]
    StdIo(#[from] std::io::Error),
    #[error(transparent)]
    Sacn(#[from] sacn::error::Error),
}

impl From<ReceiveError> for ExampleError {
    fn from(value: ReceiveError) -> Self {
        ExampleError::Sacn(sacn::error::Error::Receive(value))
    }
}

pub type ExampleResult<T> = Result<T, ExampleError>;
