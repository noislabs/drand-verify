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
    for i in 0..48 {
        buf[i] = data[i];
    }
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
    for i in 0..96 {
        buf[i] = data[i];
    }
    Ok(g2_from_fixed(buf))
}

pub fn g2_from_fixed(data: [u8; 96]) -> G2Affine {
    G2Compressed(data).into_affine().unwrap()
}
