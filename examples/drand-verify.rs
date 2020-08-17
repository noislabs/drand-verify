use hex_literal::hex;
use std::env;

use drand_verify::{g1_from_fixed, verify};

/// Public key League of Entropy Mainnet (curl -sS https://drand.cloudflare.com/info)
const PK_LEO_MAINNET: [u8; 48] = hex!("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31");

fn main() {
    let pk = g1_from_fixed(PK_LEO_MAINNET);

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("Must be called with 3 arguments");
    }
    // curl -sS https://drand.cloudflare.com/public/72785
    let round = args[0].parse::<u64>().unwrap();
    let previous_signature = hex::decode(&args[1]).unwrap();
    let signature = hex::decode(&args[2]).unwrap();

    match verify(&pk, round, &previous_signature, &signature) {
        Err(err) => eprintln!("Error during verification: {}", err),
        Ok(valid) => {
            if valid {
                println!("Hello, world!");
            } else {
                println!("Verification failed");
            }
        }
    }
}
