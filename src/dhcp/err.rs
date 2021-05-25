
#[derive(Debug)]
pub enum Error<I> {
    NomError(nom::Err<(I, nom::error::ErrorKind)>),
    NonUtf8String,
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
