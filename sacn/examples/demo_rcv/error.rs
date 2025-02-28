#[derive(Debug, thiserror::Error)]
pub enum ExampleError {
    #[error(transparent)]
    StdIo(#[from] std::io::Error),
    #[error(transparent)]
    Sacn(#[from] sacn::error::Error),
}

pub type ExampleResult<T> = Result<T, ExampleError>;
