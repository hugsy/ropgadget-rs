#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    ParsingError(goblin::error::Error),
    ThreadRuntimeError(std::boxed::Box<dyn std::any::Any + std::marker::Send>),

    GenericError(&'static str),
    MismatchFileFormatError(&'static str),
}

#[derive(Debug)]
pub struct GenericError {
    msg: String,
}

impl std::fmt::Display for GenericError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}'", self.msg)
    }
}

#[derive(Debug)]
pub struct GadgetBuildError {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<goblin::error::Error> for Error {
    fn from(error: goblin::error::Error) -> Self {
        Error::ParsingError(error)
    }
}

impl From<std::boxed::Box<dyn std::any::Any + std::marker::Send>> for Error {
    fn from(error: std::boxed::Box<dyn std::any::Any + std::marker::Send>) -> Self {
        Error::ThreadRuntimeError(error)
    }
}

#[derive(Debug)]
pub struct InvalidFormatError {
    format: String,
}

impl std::fmt::Display for InvalidFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unknown/unsupported format: {}'", self.format)
    }
}
