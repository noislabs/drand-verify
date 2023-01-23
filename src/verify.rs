use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    Bls12, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective,
};
use pairing::{group::Group, MultiMillerLoop};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;

const DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

use crate::points::{
    g1_from_fixed, g1_from_fixed_unchecked, g1_from_variable, g2_from_fixed,
    g2_from_fixed_unchecked, g2_from_variable, InvalidPoint,
};

#[derive(Debug)]
pub enum VerificationError {
    InvalidPoint { field: String, msg: String },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::InvalidPoint { field, msg } => {
                write!(f, "Invalid point for field {}: {}", field, msg)
            }
        }
    }
}

impl Error for VerificationError {}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Pubkey {
    G1(G1Affine),
    G2(G2Affine),
}

impl Pubkey {
    // Creates a public key from a 48 byte representation (point on G1)
    pub fn from_48(data: [u8; 48]) -> Result<Self, InvalidPoint> {
        Ok(Pubkey::G1(g1_from_fixed(data)?))
    }

    /// Like [`Pubkey::from_48`] without guaranteeing that the encoding represents a valid element.
    /// Only use this when you know for sure the encoding is correct.
    pub fn from_48_unchecked(data: [u8; 48]) -> Result<Self, InvalidPoint> {
        Ok(Pubkey::G1(g1_from_fixed_unchecked(data)?))
    }

    // Creates a public key from a 96 byte representation (point on G2)
    pub fn from_96(data: [u8; 96]) -> Result<Self, InvalidPoint> {
        Ok(Pubkey::G2(g2_from_fixed(data)?))
    }

    /// Creates a public key from a 96 byte representation (point on G2).
    /// Like [`Pubkey::from_96`] without guaranteeing that the encoding represents a valid element.
    /// Only use this when you know for sure the encoding is correct.
    pub fn from_96_unchecked(data: [u8; 96]) -> Result<Self, InvalidPoint> {
        Ok(Pubkey::G2(g2_from_fixed_unchecked(data)?))
    }

    /// Creates a public key from a 48 or 96 byte representation (point on G1 or G2).
    pub fn from_variable(data: &[u8]) -> Result<Self, InvalidPoint> {
        match data.len() {
            48 => {
                let mut buf = [0u8; 48];
                buf[..].clone_from_slice(data);
                Pubkey::from_48(buf)
            }
            96 => {
                let mut buf = [0u8; 96];
                buf[..].clone_from_slice(data);
                Pubkey::from_96(buf)
            }
            other => Err(InvalidPoint::InvalidLength { actual: other }),
        }
    }
}

/// Checks beacon components to see if they are valid.
///
/// For unchained mode set `previous_signature` to an empty value.
pub fn verify(
    pk: &Pubkey,
    round: u64,
    previous_signature: &[u8],
    signature: &[u8],
) -> Result<bool, VerificationError> {
    match pk {
        Pubkey::G1(pk) => {
            let msg = message(round, previous_signature);
            let msg_on_g2 = msg_to_curve_g2(&msg);
            verify_step2_g2(pk, signature, &msg_on_g2)
        }
        Pubkey::G2(pk) => {
            let msg = message(round, previous_signature);
            let msg_on_g1 = msg_to_curve_g1(&msg);
            verify_step2_g1(pk, signature, &msg_on_g1)
        }
    }
}

fn verify_step2_g1(
    pk: &G2Affine,
    signature: &[u8],
    msg_on_g1: &G1Affine,
) -> Result<bool, VerificationError> {
    let g2 = G2Affine::generator();
    let sigma = match g1_from_variable(signature) {
        Ok(sigma) => sigma,
        Err(err) => {
            return Err(VerificationError::InvalidPoint {
                field: "signature".into(),
                msg: err.to_string(),
            })
        }
    };
    Ok(fast_pairing_equality(&sigma, &g2, msg_on_g1, pk))
}

fn verify_step2_g2(
    pk: &G1Affine,
    signature: &[u8],
    msg_on_g2: &G2Affine,
) -> Result<bool, VerificationError> {
    let g1 = G1Affine::generator();
    let sigma = match g2_from_variable(signature) {
        Ok(sigma) => sigma,
        Err(err) => {
            return Err(VerificationError::InvalidPoint {
                field: "signature".into(),
                msg: err.to_string(),
            })
        }
    };
    Ok(fast_pairing_equality(&g1, &sigma, pk, msg_on_g2))
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
fn fast_pairing_equality(p: &G1Affine, q: &G2Affine, r: &G1Affine, s: &G2Affine) -> bool {
    let minus_p = -p;
    // "some number of (G1, G2) pairs" are the inputs of the miller loop
    let pair1 = (&minus_p, &G2Prepared::from(*q));
    let pair2 = (r, &G2Prepared::from(*s));
    let looped = Bls12::multi_miller_loop(&[pair1, pair2]);
    // let looped = Bls12::miller_loop([&pair1, &pair2]);
    let value = looped.final_exponentiation();
    value.is_identity().into()
}

fn message(current_round: u64, prev_sig: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update(prev_sig);
    hasher.update(round_to_bytes(current_round));
    hasher.finalize().to_vec()
}

/// https://github.com/drand/drand-client/blob/master/wasm/chain/verify.go#L28-L33
#[inline]
fn round_to_bytes(round: u64) -> [u8; 8] {
    round.to_be_bytes()
}

fn msg_to_curve_g1(msg: &[u8]) -> G1Affine {
    let g: G1Projective = HashToCurve::<ExpandMsgXmd<sha2::Sha256>>::hash_to_curve(msg, DOMAIN);
    g.into()
}

fn msg_to_curve_g2(msg: &[u8]) -> G2Affine {
    let g: G2Projective = HashToCurve::<ExpandMsgXmd<sha2::Sha256>>::hash_to_curve(msg, DOMAIN);
    g.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Public key League of Entropy Mainnet (curl -sS https://drand.cloudflare.com/info)
    const PK_LEO_MAINNET: [u8; 48] = hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31");

    /// Public key League of Entropy Mainnet (curl -sS https://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf/info)
    const PK_UNCHAINED_TESTNET: [u8; 48] = hex!("8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11");

    #[test]
    fn verify_works() {
        let pk = Pubkey::from_48(PK_LEO_MAINNET).unwrap();

        // curl -sS https://drand.cloudflare.com/public/72785
        let previous_signature = hex::decode("a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747").unwrap();
        let signature = hex::decode("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42").unwrap();
        let round: u64 = 72785;

        // good
        let result = verify(&pk, round, &previous_signature, &signature).unwrap();
        assert!(result);

        // wrong round
        let result = verify(&pk, 321, &previous_signature, &signature).unwrap();
        assert!(!result);

        // wrong previous signature
        let previous_signature_corrupted = hex::decode("6a09e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747").unwrap();
        let result = verify(&pk, round, &previous_signature_corrupted, &signature).unwrap();
        assert!(!result);

        // wrong signature
        // (use signature from https://drand.cloudflare.com/public/1 to get a valid curve point)
        let wrong_signature = hex::decode("8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655").unwrap();
        let result = verify(&pk, round, &previous_signature, &wrong_signature).unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_works_for_unchained() {
        let pk = Pubkey::from_48(PK_UNCHAINED_TESTNET).unwrap();

        // curl -sS https://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf/public/223344
        let signature = hex::decode("94f6b85df7cce7237e8e7df66d794ddad092de5d8bb6a791b97e905aa89852e506ac36a792eba7021e22eebf34891f8914bf9a8dd9233ea0a4c5ca00ef8404999f899073dd2eade61fe54077fee8168f83dcb61a758b6883b38904054e64a433").unwrap();
        let round: u64 = 223344;

        // good
        let result = verify(&pk, round, b"", &signature).unwrap();
        assert!(result);

        // wrong round
        let result = verify(&pk, round - 1, b"", &signature).unwrap();
        assert!(!result);

        // wrong signature
        // (use signature from https://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf/public/1 to get a valid curve point)
        let wrong_signature = hex::decode("86ecea71376e78abd19aaf0ad52f462a6483626563b1023bd04815a7b953da888c74f5bf6ee672a5688603ab310026230522898f33f23a7de363c66f90ffd49ec77ebf7f6c1478a9ecd6e714b4d532ab43d044da0a16fed13b4791d7fc999e2b").unwrap();
        let result = verify(&pk, round, b"", &wrong_signature).unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_works_for_g1g2_swapped() {
        // Test vectors provided by Yolan Romailler

        /// Public key for G1/G2 swap
        const PK_SWAPPED: [u8; 96] = hex!("876f6fa8073736e22f6ff4badaab35c637503718f7a452d178ce69c45d2d8129a54ad2f988ab10c9666f87ab603c59bf013409a5b500555da31720f8eec294d9809b8796f40d5372c71a44ca61226f1eb978310392f98074a608747f77e66c5a");

        let pk = Pubkey::from_96(PK_SWAPPED).unwrap();

        let signature = hex::decode("ac7c3ca14bc88bd014260f22dc016b4fe586f9313c3a549c83d195811a99a5d2d4999d4df6daec73ff51fafadd6d5bb5").unwrap();
        let round: u64 = 3;
        let result = verify(&pk, round, b"", &signature).unwrap();
        assert!(result);

        let signature = hex::decode("b4448d565ccad16beb6502f0cf84b4b8d4a67845ba894308a188731b8eb8fc5eb1b5bdcdcd370271436e1475c4786a4e").unwrap();
        let round: u64 = 4;
        let result = verify(&pk, round, b"", &signature).unwrap();
        assert!(result);
    }
}
