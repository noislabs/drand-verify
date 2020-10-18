use hex_literal::hex;
use std::env;
use std::process::exit;

use drand_verify::{derive_randomness, g1_from_fixed, verify};

/// Public key League of Entropy Mainnet (curl -sS https://drand.cloudflare.com/info)
const PK_LEO_MAINNET: [u8; 48] = hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31");

fn main_impl() -> i32 {
    let pk = g1_from_fixed(PK_LEO_MAINNET).unwrap();

    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Must be called with 3 arguments (round, previous_signature, signature)");
        return 100;
    }

    // See https://drand.cloudflare.com/public/72785 for example data of the three inputs
    let round = args[1].parse::<u64>().unwrap();
    let previous_signature = hex::decode(&args[2]).unwrap();
    let signature = hex::decode(&args[3]).unwrap();

    match verify(&pk, round, &previous_signature, &signature) {
        Err(err) => {
            eprintln!("Error during verification: {}", err);
            12
        }
        Ok(valid) => {
            if valid {
                println!("Verification succeeded");
                let randomness = derive_randomness(&signature);
                println!("Randomness: {}", hex::encode(&randomness));
                0
            } else {
                println!("Verification failed");
                1
            }
        }
    }
}

fn main() {
    exit(main_impl())
}
