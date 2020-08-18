use std::fmt;

use paired::bls12_381::{G1Affine, G1Compressed, G2Affine, G2Compressed};
use paired::EncodedPoint;

#[derive(Debug)]
pub enum InvalidPoint {
    InvalidLength { expected: usize, actual: usize },
}

impl fmt::Display for InvalidPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidPoint::InvalidLength { expected, actual } => {
                write!(f, "Invalid input length for point (must be in compressed format): Expected {}, actual: {}", expected, actual)
            }
        }
    }
}

pub fn g1_from_variable(data: &[u8]) -> Result<G1Affine, InvalidPoint> {
    if data.len() != G1Compressed::size() {
        return Err(InvalidPoint::InvalidLength {
            expected: G1Compressed::size(),
            actual: data.len(),
        });
    }

    let mut buf = [0u8; 48];
    buf[..].clone_from_slice(&data[..]);
    Ok(g1_from_fixed(buf))
}

pub fn g1_from_fixed(data: [u8; 48]) -> G1Affine {
    G1Compressed(data).into_affine().unwrap()
}

pub fn g2_from_variable(data: &[u8]) -> Result<G2Affine, InvalidPoint> {
    if data.len() != G2Compressed::size() {
        return Err(InvalidPoint::InvalidLength {
            expected: G2Compressed::size(),
            actual: data.len(),
        });
    }

    let mut buf = [0u8; 96];
    buf[..].clone_from_slice(&data[..]);
    Ok(g2_from_fixed(buf))
}

pub fn g2_from_fixed(data: [u8; 96]) -> G2Affine {
    G2Compressed(data).into_affine().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g1_from_variable_works() {
        let result = g1_from_variable(&hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31").unwrap());
        assert!(result.is_ok());

        let result = g1_from_variable(&hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af").unwrap());
        match result.unwrap_err() {
            InvalidPoint::InvalidLength { expected, actual } => {
                assert_eq!(expected, 48);
                assert_eq!(actual, 47);
            }
        }
    }

    #[test]
    fn g2_from_variable_works() {
        let result = g2_from_variable(&hex::decode("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42").unwrap());
        assert!(result.is_ok());

        let result = g2_from_variable(&hex::decode("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e").unwrap());
        match result.unwrap_err() {
            InvalidPoint::InvalidLength { expected, actual } => {
                assert_eq!(expected, 96);
                assert_eq!(actual, 95);
            }
        }
    }
}
