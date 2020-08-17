use hex_literal::hex;
use paired::bls12_381::{G1Affine, G2Affine, G2};
use paired::{CurveAffine, CurveProjective, ExpandMsgXmd, HashToCurve, PairingCurveAffine};
use sha2::{Digest, Sha256};
use std::env;

mod points;

use points::{g1_from_fixed, g2_from_variable};

const DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const PK: [u8; 48] = hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31");

fn main() {
    let pk = g1_from_fixed(PK);

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("Must be called with 3 arguments");
    }
    // curl -sS https://drand.cloudflare.com/public/72785
    let beacon = Beacon {
        round: args[0].parse::<u64>().unwrap(),
        previous_signature: hex::decode(&args[1]).unwrap(),
        signature: hex::decode(&args[2]).unwrap(),
    };
    if verify(&pk, &beacon) {
        println!("Hello, world!");
    } else {
        println!("Verification failed");
    }
}

struct Beacon {
    pub round: u64,
    pub previous_signature: Vec<u8>,
    pub signature: Vec<u8>,
}

// Verify checks beacon components to see if they are valid.
fn verify(pk: &G1Affine, beacon: &Beacon) -> bool {
    let g1 = G1Affine::one();
    let sig = g2_from_variable(&beacon.signature);

    let msg = message(beacon.round, &beacon.previous_signature);
    let msg_on_g2 = msg_to_curve(&msg);

    let lhs = g1.pairing_with(&sig);
    let rhs = pk.pairing_with(&msg_on_g2);
    lhs == rhs
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

    #[test]
    fn verify_works() {
        let pk = g1_from_fixed(PK);
        // curl -sS https://drand.cloudflare.com/public/72785
        let beacon = Beacon {
            round: 72785,
            previous_signature: hex::decode("a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747").unwrap(),
            signature: hex::decode("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42").unwrap(),
        };
        assert!(verify(&pk, &beacon))
    }
}
