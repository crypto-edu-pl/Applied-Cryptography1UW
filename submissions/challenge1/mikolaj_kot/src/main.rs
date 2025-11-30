use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use cryptopals::{
    cracker::Cracker,
    crypto::{XorType, fixed_xor, otp, repeating_xor, single_xor},
    demos,
    utils::{parse_input, Format}
};

const DEFAULT_NUM_OF_RESULTS: usize = 5;

 #[derive(Parser)]
 #[command(name = "xorall")]
 #[command(about = "A multi-mode XOR crypto tool", long_about = None)]
 struct Cli {
     #[command(subcommand)]
     command: Commands,
 }
 
 #[derive(Subcommand)]
 enum Commands {
     /// Encrypt data
     Encrypt {
         /// The input data (Hex, Base64, or Text)
         #[arg(short, long)]
         input: String,
 
         #[arg(long, value_enum, default_value_t = Format::Utf8)]
         input_format: Format,
 
         /// The Key
         #[arg(short, long)]
         key: String,
 
         #[arg(long, value_enum, default_value_t = Format::Utf8)]
         key_format: Format,
 
         /// The Algorithm
         #[arg(short = 't', long, value_enum)]
         xor_type: XorType,
     },
 
     /// Decrypt data
     Decrypt {
         #[arg(short, long)]
         input: String,
 
         #[arg(long, value_enum, default_value_t = Format::Utf8)]
         input_format: Format,
 
         #[arg(short, long)]
         key: String,
 
         #[arg(long, value_enum, default_value_t = Format::Utf8)]
         key_format: Format,
 
         #[arg(short = 't', long, value_enum)]
         xor_type: XorType,
     },
 
     /// Crack ciphertext (No key needed)
     Crack {
         #[arg(short, long)]
         input: String,
 
         #[arg(long, value_enum, default_value_t = Format::Utf8)]
         input_format: Format,
 
         /// Specific algorithm to crack (if known)
         #[arg(short = 't', long, value_enum)]
         xor_type: Option<XorType>,
     },
 
     /// Run Cryptopals Demos
     Demo {
         /// Which challenge to run
         #[arg(value_enum)]
         challenge: ChallengeId,
     },
 }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Mode {
    Encrypt,
    Decrypt,
    Crack,
}


#[derive(Clone, Debug, ValueEnum)]
enum ChallengeId {
    S1C1,
    S1C2,
    S1C3,
    S1C4,
    //S1C5,
    //S1C6,
    S4C29,
}

fn main() -> Result<()> {
    let args = Cli::parse();
    
    match args.command {
        // --- HANDLE ENCRYPTION ---
        Commands::Encrypt { input, input_format, key, key_format, xor_type } => {
            let input_bytes = parse_input(&input, input_format)?;
            let key_bytes = parse_input(&key, key_format)?;
            
            let result = run_crypto(xor_type, &input_bytes, &key_bytes)?;
            println!("Ciphertext (Hex): {}", hex::encode(result));
        },
        // --- HANDLE DECRYPTION ---
        Commands::Decrypt { input, input_format, key, key_format, xor_type } => {
            let input_bytes = parse_input(&input, input_format)?;
            let key_bytes = parse_input(&key, key_format)?;

            let result = run_crypto(xor_type, &input_bytes, &key_bytes)?;
            println!("Plaintext: {}", String::from_utf8_lossy(&result));
        },
        // --- HANDLE CRACKING ---
        Commands::Crack { input, input_format, xor_type } => {
            let input_bytes = parse_input(&input, input_format)?;
            
            // Default to Single if not specified, or implement logic to try all
            let algo = xor_type.unwrap_or(XorType::Single);

            println!("--- Cracking {:?} ---", algo);
            match algo {
                XorType::Single => {
                    let cracker = Cracker::SingleByteXor;
                    let _results = cracker.crack(&input_bytes, DEFAULT_NUM_OF_RESULTS);
                    // Print results...
                },
                XorType::Repeating => {
                    let cracker = Cracker::RepeatingKeyXor;
                    let _results = cracker.crack(&input_bytes, DEFAULT_NUM_OF_RESULTS);
                    // Print results...
                },
                _ => println!("Cracking not implemented for this type"),
            }
        },
        // --- HANDLE DEMOS ---
        Commands::Demo { challenge } => {
            println!("Running Demo: {:?}", challenge);
            match challenge {
                ChallengeId::S1C1 => demos::run_challenge_1(), // Call your demo functions
                ChallengeId::S1C2 => demos::run_challenge_2(),
                ChallengeId::S1C3 => demos::run_challenge_3(),
                ChallengeId::S1C4 => demos::run_challenge_4(),
                //ChallengeId::S1C5 => demos::run_challenge_6(),
                //ChallengeId::S1C6 => demos::run_challenge_6(),
                ChallengeId::S4C29 => demos::run_challenge_29(),
                //_ => println!("Demo not linked yet!"),
            }
        },
    }

    Ok(())
}

// Helper to dedup Encrypt/Decrypt logic
fn run_crypto(t: XorType, input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    match t {
        XorType::Single => {
            let k = *key.first().context("Single XOR requires 1 byte key")?;
            Ok(single_xor(input, k))
        },
        XorType::Fixed => Ok(fixed_xor(input, key)?),
        XorType::Otp => Ok(otp(input, key)?),
        XorType::Repeating => Ok(repeating_xor(input, key)),
    }
}