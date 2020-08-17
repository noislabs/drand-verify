use paired::bls12_381::{G1Affine, G2Affine, G2};
use paired::{CurveAffine, CurveProjective, ExpandMsgXmd, HashToCurve, PairingCurveAffine};
use sha2::{Digest, Sha256};
use std::fmt;

const DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

use super::points::g2_from_variable;

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

// Verify checks beacon components to see if they are valid.
pub fn verify(
    pk: &G1Affine,
    round: u64,
    previous_signature: &[u8],
    signature: &[u8],
) -> Result<bool, VerificationError> {
    let g1 = G1Affine::one();
    let sigma = match g2_from_variable(signature) {
        Ok(sigma) => sigma,
        Err(err) => {
            return Err(VerificationError::InvalidPoint {
                field: "signature".into(),
                msg: err.to_string(),
            })
        }
    };

    let msg = message(round, previous_signature);
    let msg_on_g2 = msg_to_curve(&msg);

    let lhs = g1.pairing_with(&sigma);
    let rhs = pk.pairing_with(&msg_on_g2);
    Ok(lhs == rhs)
}

fn message(current_round: u64, prev_sig: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.input(prev_sig);
    hasher.input(round_to_bytes(current_round));
    hasher.result().to_vec()
}

/// https://github.com/drand/drand-client/blob/master/wasm/chain/verify.go#L28-L33
#[inline]
fn round_to_bytes(round: u64) -> [u8; 8] {
    round.to_be_bytes()
}

fn msg_to_curve(msg: &[u8]) -> G2Affine {
    let g = <G2 as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, DOMAIN);
    g.into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::points::g1_from_fixed;
    use hex_literal::hex;

    /// Public key League of Entropy Mainnet (curl -sS https://drand.cloudflare.com/info)
    const PK_LEO_MAINNET: [u8; 48] = hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31");

    #[test]
    fn verify_works() {
        let pk = g1_from_fixed(PK_LEO_MAINNET);
        // curl -sS https://drand.cloudflare.com/public/72785
        let previous_signature = hex::decode("a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747").unwrap();
        let signature = hex::decode("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42").unwrap();
        let result = verify(&pk, 72785, &previous_signature, &signature).unwrap();
        assert_eq!(result, true);
    }
}
