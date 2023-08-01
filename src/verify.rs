use std::error::Error;
use std::fmt;

#[cfg(feature = "arkworks")]
use crate::verify_arkworks::*;
#[cfg(not(feature = "arkworks"))]
use crate::verify_zkcrypro::*;
#[cfg(feature = "arkworks")]
use sha2_v10::{Digest, Sha256};
#[cfg(not(feature = "arkworks"))]
use sha2_v9::{Digest, Sha256};

#[cfg(feature = "arkworks")]
use ark_bls12_381::{G1Affine, G2Affine};
#[cfg(not(feature = "arkworks"))]
use bls12_381::{G1Affine, G2Affine};

use crate::points::{
    g1_from_fixed, g1_from_fixed_unchecked, g1_from_variable, g2_from_fixed,
    g2_from_fixed_unchecked, g2_from_variable, InvalidPoint,
};

// See https://github.com/drand/kyber-bls12381/issues/22 and
// https://github.com/drand/drand/pull/1249
const DOMAIN_HASH_TO_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const DOMAIN_HASH_TO_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Point on G1
pub struct G1(G1Affine);

/// Point on G2
pub struct G2(G2Affine);

pub trait Pubkey: Sized {
    /// The curve (G1 or G2) on which the public key lives
    type This;

    /// The type in which this point is expressed in binary data (either `[u8; 48]` or `[u8; 96]`)
    type ThisCompressed;

    /// The other curve (G2 or G1) on which the signature lives
    type Other;

    fn msg_to_curve(msg: &[u8]) -> Self::Other;

    fn from_fixed(data: Self::ThisCompressed) -> Result<Self, InvalidPoint>;

    fn from_fixed_unchecked(data: Self::ThisCompressed) -> Result<Self, InvalidPoint>;

    fn from_variable(data: &[u8]) -> Result<Self, InvalidPoint>;

    /// This is part of `verify` but you can call it explicitely in case you already
    /// have a message hashed to the curve.
    fn verify_step2(
        &self,
        signature: &[u8],
        msg_on_curve: &Self::Other,
    ) -> Result<bool, VerificationError>;

    /// The high level verification method for a drand beacon.
    ///
    /// `previous_signature` should be set to an empty slice for the unchained mode.
    fn verify(
        &self,
        round: u64,
        previous_signature: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerificationError> {
        let msg = message(round, previous_signature);
        let msg_on_curve = Self::msg_to_curve(&msg);
        self.verify_step2(signature, &msg_on_curve)
    }
}

/// The pubkey type for drand networks with scheme ID pedersen-bls-chained or pedersen-bls-unchained.
pub struct G1Pubkey(G1);

impl Pubkey for G1Pubkey {
    type This = G1;
    type ThisCompressed = [u8; 48];
    type Other = G2;

    fn msg_to_curve(msg: &[u8]) -> Self::Other {
        G2(hash_to_curve_g2(msg, DOMAIN_HASH_TO_G2))
    }

    fn from_fixed(data: [u8; 48]) -> Result<Self, InvalidPoint> {
        Ok(Self(G1(g1_from_fixed(data)?)))
    }

    fn from_fixed_unchecked(data: [u8; 48]) -> Result<Self, InvalidPoint> {
        Ok(Self(G1(g1_from_fixed_unchecked(data)?)))
    }

    fn from_variable(data: &[u8]) -> Result<Self, InvalidPoint> {
        Ok(Self(G1(g1_from_variable(data)?)))
    }

    /// Takes this public key and verifies the signature with it.
    /// The message has to be created with `Self::msg_to_curve`.
    fn verify_step2(
        &self,
        signature: &[u8],
        msg_on_curve: &Self::Other,
    ) -> Result<bool, VerificationError> {
        let g1 = g1_generator();
        let sigma = match g2_from_variable(signature) {
            Ok(sigma) => sigma,
            Err(err) => {
                return Err(VerificationError::InvalidPoint {
                    field: "signature".into(),
                    msg: err.to_string(),
                })
            }
        };
        let r = (self.0).0;
        Ok(fast_pairing_equality(&g1, &sigma, &r, &msg_on_curve.0))
    }
}

/// The pubkey type for drand networks with scheme ID bls-unchained-on-g1.
pub struct G2Pubkey(G2);

impl Pubkey for G2Pubkey {
    type This = G2;
    type ThisCompressed = [u8; 96];
    type Other = G1;

    fn msg_to_curve(msg: &[u8]) -> Self::Other {
        // The usage of DOMAIN_HASH_TO_G2 here is needed to be compatible to a bug in drand's fastnet.
        // See https://github.com/noislabs/drand-verify/pull/22 for more information about that topic.
        G1(hash_to_curve_g1(msg, DOMAIN_HASH_TO_G2))
    }

    fn from_fixed(data: [u8; 96]) -> Result<Self, InvalidPoint> {
        Ok(Self(G2(g2_from_fixed(data)?)))
    }

    fn from_fixed_unchecked(data: [u8; 96]) -> Result<Self, InvalidPoint> {
        Ok(Self(G2(g2_from_fixed_unchecked(data)?)))
    }

    fn from_variable(data: &[u8]) -> Result<Self, InvalidPoint> {
        Ok(Self(G2(g2_from_variable(data)?)))
    }

    /// Takes this public key and verifies the signature with it.
    /// The message has to be created with `Self::msg_to_curve`.
    fn verify_step2(
        &self,
        signature: &[u8],
        msg_on_curve: &Self::Other,
    ) -> Result<bool, VerificationError> {
        let g2 = g2_generator();
        let sigma = match g1_from_variable(signature) {
            Ok(sigma) => sigma,
            Err(err) => {
                return Err(VerificationError::InvalidPoint {
                    field: "signature".into(),
                    msg: err.to_string(),
                })
            }
        };
        let s = (self.0).0;
        Ok(fast_pairing_equality(&sigma, &g2, &msg_on_curve.0, &s))
    }
}

/// The pubkey type for drand networks with scheme ID bls-unchained-g1-rfc9380.
pub struct G2PubkeyRfc(G2);

impl Pubkey for G2PubkeyRfc {
    type This = G2;
    type ThisCompressed = [u8; 96];
    type Other = G1;

    fn msg_to_curve(msg: &[u8]) -> Self::Other {
        G1(hash_to_curve_g1(msg, DOMAIN_HASH_TO_G1))
    }

    fn from_fixed(data: [u8; 96]) -> Result<Self, InvalidPoint> {
        Ok(Self(G2(g2_from_fixed(data)?)))
    }

    fn from_fixed_unchecked(data: [u8; 96]) -> Result<Self, InvalidPoint> {
        Ok(Self(G2(g2_from_fixed_unchecked(data)?)))
    }

    fn from_variable(data: &[u8]) -> Result<Self, InvalidPoint> {
        Ok(Self(G2(g2_from_variable(data)?)))
    }

    /// Takes this public key and verifies the signature with it.
    /// The message has to be created with `Self::msg_to_curve`.
    fn verify_step2(
        &self,
        signature: &[u8],
        msg_on_curve: &Self::Other,
    ) -> Result<bool, VerificationError> {
        let g2 = g2_generator();
        let sigma = match g1_from_variable(signature) {
            Ok(sigma) => sigma,
            Err(err) => {
                return Err(VerificationError::InvalidPoint {
                    field: "signature".into(),
                    msg: err.to_string(),
                })
            }
        };
        let s = (self.0).0;
        Ok(fast_pairing_equality(&sigma, &g2, &msg_on_curve.0, &s))
    }
}

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

fn message(current_round: u64, prev_sig: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(prev_sig);
    hasher.update(round_to_bytes(current_round));
    hasher.finalize().into()
}

/// https://github.com/drand/drand-client/blob/master/wasm/chain/verify.go#L28-L33
#[inline]
fn round_to_bytes(round: u64) -> [u8; 8] {
    round.to_be_bytes()
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
        let pk = G1Pubkey::from_fixed(PK_LEO_MAINNET).unwrap();

        // curl -sS https://drand.cloudflare.com/public/72785
        let previous_signature = hex::decode("a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747").unwrap();
        let signature = hex::decode("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42").unwrap();
        let round: u64 = 72785;

        // good
        let result = pk.verify(round, &previous_signature, &signature).unwrap();
        assert!(result);

        // wrong round
        let result = pk.verify(321, &previous_signature, &signature).unwrap();
        assert!(!result);

        // wrong previous signature
        let previous_signature_corrupted = hex::decode("6a09e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747").unwrap();
        let result = pk
            .verify(round, &previous_signature_corrupted, &signature)
            .unwrap();
        assert!(!result);

        // wrong signature
        // (use signature from https://drand.cloudflare.com/public/1 to get a valid curve point)
        let wrong_signature = hex::decode("8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655").unwrap();
        let result = pk
            .verify(round, &previous_signature, &wrong_signature)
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_works_for_unchained() {
        let pk = G1Pubkey::from_fixed(PK_UNCHAINED_TESTNET).unwrap();

        // curl -sS https://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf/public/223344
        let signature = hex::decode("94f6b85df7cce7237e8e7df66d794ddad092de5d8bb6a791b97e905aa89852e506ac36a792eba7021e22eebf34891f8914bf9a8dd9233ea0a4c5ca00ef8404999f899073dd2eade61fe54077fee8168f83dcb61a758b6883b38904054e64a433").unwrap();
        let round: u64 = 223344;

        // good
        let result = pk.verify(round, b"", &signature).unwrap();
        assert!(result);

        // wrong round
        let result = pk.verify(round - 1, b"", &signature).unwrap();
        assert!(!result);

        // wrong signature
        // (use signature from https://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf/public/1 to get a valid curve point)
        let wrong_signature = hex::decode("86ecea71376e78abd19aaf0ad52f462a6483626563b1023bd04815a7b953da888c74f5bf6ee672a5688603ab310026230522898f33f23a7de363c66f90ffd49ec77ebf7f6c1478a9ecd6e714b4d532ab43d044da0a16fed13b4791d7fc999e2b").unwrap();
        let result = pk.verify(round, b"", &wrong_signature).unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_works_for_g1g2_swapped() {
        // Test vectors (Public key for G1/G2 swaped) provided by Yolan Romailler
        const PK_HEX: [u8; 96] = hex!("876f6fa8073736e22f6ff4badaab35c637503718f7a452d178ce69c45d2d8129a54ad2f988ab10c9666f87ab603c59bf013409a5b500555da31720f8eec294d9809b8796f40d5372c71a44ca61226f1eb978310392f98074a608747f77e66c5a");
        let pk = G2Pubkey::from_fixed(PK_HEX).unwrap();

        let signature = hex::decode("ac7c3ca14bc88bd014260f22dc016b4fe586f9313c3a549c83d195811a99a5d2d4999d4df6daec73ff51fafadd6d5bb5").unwrap();
        let round: u64 = 3;
        let result = pk.verify(round, b"", &signature).unwrap();
        assert!(result);

        let signature = hex::decode("b4448d565ccad16beb6502f0cf84b4b8d4a67845ba894308a188731b8eb8fc5eb1b5bdcdcd370271436e1475c4786a4e").unwrap();
        let round: u64 = 4;
        let result = pk.verify(round, b"", &signature).unwrap();
        assert!(result);

        // Tests from https://pl-us.testnet.drand.sh/f3827d772c155f95a9fda8901ddd59591a082df5ac6efe3a479ddb1f5eeb202c/info
        const PK_HEX2: [u8; 96] = hex!("8f6e58c3dbc6d7e58e32baee6881fecc854161b4227c40b01ae7f0593cea964599648f91a0fa2d6b489a7fb0a552b959014007e05d0c069991be4d064bbe28275bd4c3a3cabf16c48f86f4566909dd6eb6d0e84fd6069c414562ca6abf5fdc13");
        let pk = G2Pubkey::from_fixed(PK_HEX2).unwrap();

        let signature = hex::decode("a7fdfc9c5c31ba96011e89931668239daa368eaf2fbd03fafa38e0c336d0653d921f114b65ceb1a9ef781492d61e0d0a").unwrap();
        let round: u64 = 375953;
        let result = pk.verify(round, b"", &signature).unwrap();
        assert!(result);

        let signature = hex::decode("b8fe4f9f0fe05a70b027460379d30b02775b7cf625755bf304a94ac2bddb08609fdfbfc23c75c671d6e0a5727392507f").unwrap();
        let round: u64 = 375965;
        let result = pk.verify(round, b"", &signature).unwrap();
        assert!(result);

        // Tests from https://api3.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/info
        const PK_HEX3: [u8; 96] = hex!("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e");
        let pk = G2Pubkey::from_fixed(PK_HEX3).unwrap();

        // https://api3.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/1
        let signature = hex::decode("9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0").unwrap();
        let round: u64 = 1;
        let result = pk.verify(round, b"", &signature).unwrap();
        assert!(result);

        // https://api3.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/23456
        let signature = hex::decode("98401ef9833e75bf06fda3243e4fcf6d075d62b45c2a59d26df5d5fcbdfd0c14ee89fc035abd5528a8c25b68fbecae65").unwrap();
        let round: u64 = 23456;
        let result = pk.verify(round, b"", &signature).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_works_for_g1g2_swapped_rfc() {
        // Test vectors (Public key for G1/G2 swaped) provided by Yolan Romailler
        // https://gist.github.com/webmaster128/43dbd8726bd00c1252c72ae74ca3d220

        const PK_HEX: [u8; 96] = hex!("a1ee12542360bf75742bcade13d6134e7d5283d9eb782887c47d3d9725f05805d37b0106b7f744395bf82c175dd7434a169e998f188a657a030d588892c0cd2c01f996aaf331c4d8bc5b9734bbe261d09e7d2d39ef88b635077f262bd7bbb30f");
        let pk = G2PubkeyRfc::from_fixed(PK_HEX).unwrap();

        let signature = hex::decode("b98dae74f6a9d2ec79d75ba273dcfda86a45d589412860eb4c0fd056b00654dbf667c1b6884987c9aee0d43f8ba9db52").unwrap();
        let round: u64 = 3;
        let result = pk.verify(round, b"", &signature).unwrap();
        assert!(result);

        let signature = hex::decode("962c2b2969e8f3351cf5cc457b04ecbf0c65bd79f4c1ee3bd0205f581368aaaa0cdeb1531a0709d39ef06a8ba1e1bb93").unwrap();
        let round: u64 = 4;
        let result = pk.verify(round, b"", &signature).unwrap();
        assert!(result);

        let signature = hex::decode("a054dafb27a4a4fb9e06b17b30da3e0c7b13b4ca8e1dec3c6775f81758587029aa358523f2e7e62204018347db7cbd1c").unwrap();
        let round: u64 = 6;
        let result = pk.verify(round, b"", &signature).unwrap();
        assert!(result);
    }
}
