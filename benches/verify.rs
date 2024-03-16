#![feature(test)]

extern crate test;

use drand_verify::{G1Pubkey, G2Pubkey, Pubkey};
use hex_literal::hex;

/// Public key League of Entropy Mainnet (curl -sS https://drand.cloudflare.com/info)
const PK_LEO_MAINNET: [u8; 48] = hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31");

// Fastnet is the unchained 3s mainnet launched Mar 1st, 2023
// https://api3.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/info
const PK_FASTNET: [u8; 96] = hex!("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e");

#[bench]
fn bench_verify_classic_mainnet(b: &mut ::test::Bencher) {
    let pk = G1Pubkey::from_fixed(PK_LEO_MAINNET).unwrap();

    // curl -sS https://drand.cloudflare.com/public/72785
    let previous_signature = hex::decode("a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747").unwrap();
    let signature = hex::decode("82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42").unwrap();
    let round: u64 = 72785;

    b.iter(|| {
        let result = pk.verify(round, &previous_signature, &signature).unwrap();
        result
    });
}

#[bench]
fn bench_verify_fastnet(b: &mut ::test::Bencher) {
    let pk = G2Pubkey::from_fixed(PK_FASTNET).unwrap();

    // curl -sS https://drand.cloudflare.com/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/72785
    let signature = hex::decode("83f2bcb12b772602f27a1ad130a33781014ac73e82098580e934a5b5e4ad57ceff27ad22fd6344b33af9675e0d0b5e27").unwrap();
    let round: u64 = 72785;

    b.iter(|| {
        let result = pk.verify(round, &[], &signature).unwrap();
        result
    });
}
