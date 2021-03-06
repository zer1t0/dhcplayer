
#[derive(Debug)]
pub enum Error<I> {
    NomError(nom::Err<(I, nom::error::ErrorKind)>),
    NonUtf8String,
}

impl<I> From<nom::Err<(I, nom::error::ErrorKind)>> for Error<I> {
    fn from(error: nom::Err<(I, nom::error::ErrorKind)>) -> Self {
        return Self::NomError(error);
    }
}

impl<I> nom::error::ParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Error::NomError(nom::Err::Error((input, kind)))
    }

    fn append(_input: I, _kind: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

pub type IResult<I, O> = nom::IResult<I, O, Error<I>>;
