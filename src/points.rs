use std::fmt;

use bls12_381::{G1Affine, G2Affine};

#[derive(Debug)]
pub enum InvalidPoint {
    /// Length is not 48 or 96 bytes
    InvalidLength {
        actual: usize,
    },
    UnexpectedLength {
        expected: usize,
        actual: usize,
    },
    DecodingError {},
}

impl fmt::Display for InvalidPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidPoint::InvalidLength { actual } => {
                write!(f, "Invalid input length for point (must be in compressed format, 48 or 96 bytes): {actual}")
            }
            InvalidPoint::UnexpectedLength { expected, actual } => {
                write!(f, "Unexpected input length for point (must be in compressed format): Expected {}, actual: {}", expected, actual)
            }
            InvalidPoint::DecodingError {} => {
                write!(f, "Invalid point")
            }
        }
    }
}

pub fn g1_from_variable(data: &[u8]) -> Result<G1Affine, InvalidPoint> {
    if data.len() != 48 {
        return Err(InvalidPoint::UnexpectedLength {
            expected: 48,
            actual: data.len(),
        });
    }

    let mut buf = [0u8; 48];
    buf[..].clone_from_slice(data);
    g1_from_fixed(buf)
}

pub fn g2_from_variable(data: &[u8]) -> Result<G2Affine, InvalidPoint> {
    if data.len() != 96 {
        return Err(InvalidPoint::UnexpectedLength {
            expected: 96,
            actual: data.len(),
        });
    }

    let mut buf = [0u8; 96];
    buf[..].clone_from_slice(data);
    g2_from_fixed(buf)
}

pub fn g1_from_fixed(data: [u8; 48]) -> Result<G1Affine, InvalidPoint> {
    Option::from(G1Affine::from_compressed(&data)).ok_or(InvalidPoint::DecodingError {})
}

/// Like [`g1_from_fixed`] without guaranteeing that the encoding represents a valid element.
/// Only use this when you know for sure the encoding is correct.
pub fn g1_from_fixed_unchecked(data: [u8; 48]) -> Result<G1Affine, InvalidPoint> {
    Option::from(G1Affine::from_compressed_unchecked(&data)).ok_or(InvalidPoint::DecodingError {})
}

pub fn g2_from_fixed(data: [u8; 96]) -> Result<G2Affine, InvalidPoint> {
    Option::from(G2Affine::from_compressed(&data)).ok_or(InvalidPoint::DecodingError {})
}

/// Like [`g2_from_fixed`] without guaranteeing that the encoding represents a valid element.
/// Only use this when you know for sure the encoding is correct.
pub fn g2_from_fixed_unchecked(data: [u8; 96]) -> Result<G2Affine, InvalidPoint> {
    Option::from(G2Affine::from_compressed_unchecked(&data)).ok_or(InvalidPoint::DecodingError {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn g1_from_variable_works() {
        let result = g1_from_variable(&hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31").unwrap());
        assert!(result.is_ok());

        let result = g1_from_variable(&hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af").unwrap());
        match result.unwrap_err() {
            InvalidPoint::UnexpectedLength { expected, actual } => {
                assert_eq!(expected, 48);
                assert_eq!(actual, 47);
            }
            err => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn g2_from_variable_works() {
        let result = g2_from_variable(&hex::decode("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42").unwrap());
        assert!(result.is_ok());

        let result = g2_from_variable(&hex::decode("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e").unwrap());
        match result.unwrap_err() {
            InvalidPoint::UnexpectedLength { expected, actual } => {
                assert_eq!(expected, 96);
                assert_eq!(actual, 95);
            }
            err => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn g1_from_fixed_works() {
        let result = g1_from_fixed(hex_literal::hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"));
        assert!(result.is_ok());

        let result = g1_from_fixed(hex_literal::hex!("118f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"));
        match result.unwrap_err() {
            InvalidPoint::DecodingError {} => {}
            err => panic!("Unexpected error: {:?}", err),
        }

        let result = g1_from_fixed(hex_literal::hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af22"));
        match result.unwrap_err() {
            InvalidPoint::DecodingError {} => {}
            err => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn g1_from_fixed_unchecked_works() {
        let data = hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31");
        let a = g1_from_fixed_unchecked(data).unwrap();
        let b = g1_from_fixed(data).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn g2_from_fixed_works() {
        let result = g2_from_fixed(hex_literal::hex!("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42"));
        assert!(result.is_ok());

        let result = g2_from_fixed(hex_literal::hex!("11f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42"));
        match result.unwrap_err() {
            InvalidPoint::DecodingError {} => {}
            err => panic!("Unexpected error: {:?}", err),
        }

        let result = g2_from_fixed(hex_literal::hex!("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e44"));
        match result.unwrap_err() {
            InvalidPoint::DecodingError {} => {}
            err => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn g2_from_fixed_unchecked_works() {
        let data = hex!("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42");
        let a = g2_from_fixed_unchecked(data).unwrap();
        let b = g2_from_fixed(data).unwrap();
        assert_eq!(a, b);
    }
}
