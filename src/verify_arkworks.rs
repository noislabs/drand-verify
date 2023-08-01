use ark_bls12_381::{g1, g2, G1Affine, G2Affine};
use ark_ec::{
    bls12::Bls12,
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    models::short_weierstrass,
    pairing::Pairing,
    AffineRepr,
};
use ark_ff::{field_hashers::DefaultFieldHasher, Zero};
use sha2_v10::Sha256;
use std::ops::Neg;

pub fn hash_to_curve_g1(msg: &[u8], dst: &[u8]) -> G1Affine {
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g1::Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<g1::Config>,
    >::new(dst)
    .expect("cannot initialise mapper for sha2 to BLS12-381 G1");
    mapper.hash(msg).expect("hash cannot be mapped to G1")
}

pub fn hash_to_curve_g2(msg: &[u8], dst: &[u8]) -> G2Affine {
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g2::Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<g2::Config>,
    >::new(dst)
    .expect("cannot initialise mapper for sha2 to BLS12-381 G2");
    mapper.hash(msg).expect("hash cannot be mapped to G2")
}

/// Checks if e(p, q) == e(r, s)
///
/// See https://hackmd.io/@benjaminion/bls12-381#Final-exponentiation.
///
/// Optimized by this trick:
///   Instead of doing e(a,b) (in G2) multiplied by e(-c,d) (in G2)
///   (which is costly is to multiply in G2 because these are very big numbers)
///   we can do FinalExponentiation(MillerLoop( [a,b], [-c,d] )) which is the same
///   in an optimized way.
pub fn fast_pairing_equality(p: &G1Affine, q: &G2Affine, r: &G1Affine, s: &G2Affine) -> bool {
    let minus_p = p.neg();
    // "some number of (G1, G2) pairs" are the inputs of the miller loop
    let looped = Bls12::<ark_bls12_381::Config>::multi_miller_loop([minus_p, *r], [*q, *s]);
    let value = Bls12::final_exponentiation(looped);
    value.unwrap().is_zero()
}

pub fn g1_generator() -> G1Affine {
    G1Affine::generator()
}

pub fn g2_generator() -> G2Affine {
    G2Affine::generator()
}
