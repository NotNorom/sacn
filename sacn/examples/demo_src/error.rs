use sacn::{error::{ReceiveError, SourceError}, priority::PriorityError};

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

impl From<SourceError> for ExampleError {
    fn from(value: SourceError) -> Self {
        ExampleError::Sacn(sacn::error::Error::Source(value))
    }
}

impl From<PriorityError> for ExampleError {
    fn from(value: PriorityError) -> Self {
        ExampleError::Sacn(sacn::error::Error::Source(SourceError::PriorityError(value)))
    }
}

pub type ExampleResult<T> = Result<T, ExampleError>;
