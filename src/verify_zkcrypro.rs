use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective};
use pairing::{group::Group, MultiMillerLoop};
use sha2_v9::Sha256;

pub fn hash_to_curve_g1(msg: &[u8], dst: &[u8]) -> G1Affine {
    let g: G1Projective = HashToCurve::<ExpandMsgXmd<Sha256>>::hash_to_curve(msg, dst);
    g.into()
}

pub fn hash_to_curve_g2(msg: &[u8], dst: &[u8]) -> G2Affine {
    let g: G2Projective = HashToCurve::<ExpandMsgXmd<Sha256>>::hash_to_curve(msg, dst);
    g.into()
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
    let minus_p = -p;
    // "some number of (G1, G2) pairs" are the inputs of the miller loop
    let pair1 = (&minus_p, &G2Prepared::from(*q));
    let pair2 = (r, &G2Prepared::from(*s));
    let looped = Bls12::multi_miller_loop(&[pair1, pair2]);
    // let looped = Bls12::miller_loop([&pair1, &pair2]);
    let value = looped.final_exponentiation();
    value.is_identity().into()
}

pub fn g1_generator() -> G1Affine {
    G1Affine::generator()
}

pub fn g2_generator() -> G2Affine {
    G2Affine::generator()
}
