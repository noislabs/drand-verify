use paired::bls12_381::{G1Affine, G1Compressed, G2Affine, G2Compressed};
use paired::EncodedPoint;

pub fn g1_from_variable(data: &[u8]) -> G1Affine {
    if data.len() != G1Compressed::size() {
        panic!("Invalid length");
    }

    let mut buf = [0u8; 48];
    for i in 0..48 {
        buf[i] = data[i];
    }
    g1_from_fixed(buf)
}

pub fn g1_from_fixed(data: [u8; 48]) -> G1Affine {
    G1Compressed(data).into_affine().unwrap()
}

pub fn g2_from_variable(data: &[u8]) -> G2Affine {
    if data.len() != G2Compressed::size() {
        panic!("Invalid length");
    }

    let mut buf = [0u8; 96];
    for i in 0..96 {
        buf[i] = data[i];
    }
    g2_from_fixed(buf)
}

pub fn g2_from_fixed(data: [u8; 96]) -> G2Affine {
    G2Compressed(data).into_affine().unwrap()
}
