extern crate core;
extern crate rand;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use ascon_aead::Ascon128;
use chacha20poly1305::ChaCha20Poly1305;
use hc_256::cipher::{KeyIvInit, StreamCipher};
use hc_256::Hc256;
use mosquitto_rs::{Client, Error, QoS};
use openssl::symm::{decrypt, encrypt, Cipher};
use rand::Rng;
use std::io;
use std::time::{Duration, Instant};
#[tokio::main]
async fn main() {
    let mut iterations = String::new();
    let mut string_size = String::new();
    let stdin = io::stdin();
    println!("Enter the number of iterations you want to run: ");
    stdin.read_line(&mut iterations);
    let iterations: u32 = iterations.trim().parse().expect("Please enter a number");
    println!("Enter the size (bytes) of the string you want to encrypt: ");
    stdin.read_line(&mut string_size);
    let string_size: usize = string_size.trim().parse().expect("Please enter a number");
    println!(
        "Starting Test for {} Iterations and {} bytes of payload ",
        iterations, string_size
    );
    let msg = generate_random_string(string_size);
    let msg = msg.as_str();
    println!("Generated Payload: {}", msg);
    println!();
    let mut client = Client::with_auto_id().unwrap();
    let aes_key = Aes256Gcm::generate_key(OsRng);

    let rc = client
        .connect("localhost", 1883, std::time::Duration::from_secs(5), None)
        .await
        .unwrap();
    println!("Connected To Mosquitto Broker: {}", rc);

    let subscriptions = client.subscriber().unwrap();

    client.subscribe("test", QoS::AtMostOnce).await.unwrap();
    println!("Subscribed to Topic: test");

    // let msg = "Hello World! This is a test message. We are testing different encryption algorithms.
    // This is a test message. We are testing different encryption algorithms. This is a test message.";

    println!();
    println!("================== AES Test STARTED ======================");
    //AES Test Start
    let mut aes_encryption_time = 0;
    let mut aes_decryption_time = 0;
    for _ in 0..iterations {
        // print!(".");
        let cipher = Aes256Gcm::new(&aes_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let start = Instant::now();
        let aes_ciphertext = cipher.encrypt(&nonce, msg.as_bytes()).unwrap();
        let elapsed = start.elapsed();
        aes_encryption_time += elapsed.as_micros();
        client
            .publish("test", aes_ciphertext.as_slice(), QoS::AtMostOnce, false)
            .await
            .unwrap();
        // println!("AES published. It took {}us to encrypt and send {} bytes of data", elapsed.as_micros(), msg.len());

        if let Ok(msg) = subscriptions.recv().await {
            let start = Instant::now();
            let plaintext = cipher.decrypt(&nonce, msg.payload.as_slice()).unwrap();
            let elapsed = start.elapsed();
            aes_decryption_time += elapsed.as_micros();
            let plaintext = std::str::from_utf8(&plaintext).unwrap();
            // println!("AES Received. It took {}us to decrypt {} bytes of data", elapsed.as_micros(), plaintext.len());
        }
    }
    // println!();
    println!(
        "Avg. AES Encryption Time: {}us",
        aes_encryption_time / (iterations as u128)
    );
    println!(
        "Avg. AES Decryption Time: {}us",
        aes_decryption_time / (iterations as u128)
    );
    println!("================== AES Test ENDED ======================");

    println!();
    println!("================== DES Test START ======================");
    let mut des_encryption_time = 0;
    let mut des_decryption_time = 0;
    for _ in 0..iterations {
        // print!(".");
        let des_string = "12345689".as_bytes()[0..8].to_vec();
        let cipher = Cipher::des_ecb();
        let start = Instant::now();
        let des_ciphertext = encrypt(cipher, des_string.as_slice(), None, msg.as_bytes()).unwrap();
        let elapsed = start.elapsed();
        des_encryption_time += elapsed.as_micros();
        client
            .publish("test", des_ciphertext.as_slice(), QoS::AtMostOnce, false)
            .await
            .unwrap();
        // println!("DES published. It took {}us to encrypt and send {} bytes of data", elapsed.as_micros(), msg.len());
        if let Ok(msg) = subscriptions.recv().await {
            let start = Instant::now();
            let plaintext = decrypt(cipher, des_string.as_slice(), None, &msg.payload)
                .expect("Error decrypting DES");
            let elapsed = start.elapsed();
            des_decryption_time += elapsed.as_micros();
            let plaintext = std::str::from_utf8(&plaintext).unwrap();
            // println!("DES Received. It took {}us to decrypt {} bytes of data", elapsed.as_micros(), plaintext.len());
        }
    }
    // println!();
    println!(
        "Avg. DES Encryption Time: {}us",
        des_encryption_time / (iterations as u128)
    );
    println!(
        "Avg. DES Decryption Time: {}us",
        des_decryption_time / (iterations as u128)
    );
    println!("================== DES Test ENDED ======================");

    println!();
    println!("================== ChaCha20 Test START ======================");
    let mut chacha_encryption_time = 0;
    let mut chacha_decryption_time = 0;
    for _ in 0..iterations {
        // print!(".");
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let start = Instant::now();
        let chacha_ciphertext = cipher.encrypt(&nonce, msg.as_bytes()).unwrap();
        let elapsed = start.elapsed();
        chacha_encryption_time += elapsed.as_micros();
        client
            .publish("test", chacha_ciphertext.as_slice(), QoS::AtMostOnce, false)
            .await
            .unwrap();
        // println!("ChaCha20 published. It took {}us to encrypt and send {} bytes of data", elapsed.as_micros(), msg.len());
        if let Ok(msg) = subscriptions.recv().await {
            let start = Instant::now();
            let plaintext = cipher
                .decrypt(&nonce, msg.payload.as_slice().as_ref())
                .unwrap();
            let elapsed = start.elapsed();
            chacha_decryption_time += elapsed.as_micros();
            let plaintext = std::str::from_utf8(&plaintext).unwrap();
            // println!("ChaCha20 Received. It took {}us to decrypt {} bytes of data", elapsed.as_micros(), plaintext.len());
        }
    }
    // println!();
    println!(
        "Avg. ChaCha20 Encryption Time: {}us",
        chacha_encryption_time / (iterations as u128)
    );
    println!(
        "Avg. ChaCha20 Decryption Time: {}us",
        chacha_decryption_time / (iterations as u128)
    );
    println!("================== ChaCha20 Test ENDED ======================");

    println!();
    println!("================== HC256 Test START ======================");
    let mut hc256_encryption_time = 0;
    let mut hc256_decryption_time = 0;
    for _ in 0..iterations {
        // print!(".");
        let key = [0x42; 32];
        let nonce = [0x24; 32];
        let mut cipher = Hc256::new(&key.into(), &nonce.into());
        let mut buffer = msg.clone().as_bytes();
        let start = Instant::now();
        cipher.apply_keystream(&mut buffer.to_owned());
        let elapsed = start.elapsed();
        hc256_encryption_time += elapsed.as_micros();
        client
            .publish("test", buffer, QoS::AtMostOnce, false)
            .await
            .unwrap();
        // println!("HC256 published. It took {}us to encrypt and send {} bytes of data", elapsed.as_micros(), msg.len());
        if let Ok(msg) = subscriptions.recv().await {
            let mut cipher = Hc256::new(&key.into(), &nonce.into());
            let mut mesg = msg.payload.as_slice().as_ref();
            let start = Instant::now();
            cipher.apply_keystream(&mut mesg.to_owned());
            let elapsed = start.elapsed();
            hc256_decryption_time += elapsed.as_micros();
            let plaintext = std::str::from_utf8(&mesg).unwrap();
            // println!("HC256 Received. It took {}us to decrypt {} bytes of data", elapsed.as_micros(), plaintext.len());
        }
    }
    // println!();
    println!(
        "Avg. HC256 Encryption Time: {}us",
        hc256_encryption_time / (iterations as u128)
    );
    println!(
        "Avg. HC256 Decryption Time: {}us",
        hc256_decryption_time / (iterations as u128)
    );
    println!("================== HC256 Test ENDED ======================");

    println!();
    println!("================== ASCON Test START ======================");
    let mut ascon_encryption_time = 0;
    let mut ascon_decryption_time = 0;
    for _ in 0..iterations {
        // print!(".");
        let key = Key::<Ascon128>::from_slice(b"very secret key.");
        let cipher = Ascon128::new(key);
        let nonce = ascon_aead::Nonce::<Ascon128>::from_slice(b"unique nonce 012");
        let start = Instant::now();
        let ascon_ciphertext = cipher
            .encrypt(nonce, msg.as_bytes())
            .expect("encryption failure!");
        let elapsed = start.elapsed();
        ascon_encryption_time += elapsed.as_micros();
        client
            .publish("test", ascon_ciphertext.as_slice(), QoS::AtMostOnce, false)
            .await
            .unwrap();
        // println!("ASCON published. It took {}us to encrypt and send {} bytes of data", elapsed.as_micros(), msg.len());
        if let Ok(msg) = subscriptions.recv().await {
            let start = Instant::now();
            let plaintext = cipher
                .decrypt(nonce, msg.payload.as_slice())
                .expect("decryption failure!");
            let elapsed = start.elapsed();
            ascon_decryption_time += elapsed.as_micros();
            let plaintext = std::str::from_utf8(&plaintext).unwrap();
            // println!("ASCON Received. It took {}us to decrypt {} bytes of data", elapsed.as_micros(), plaintext.len());
        }
    }
    println!(
        "Avg. ASCON Encryption Time: {}us",
        ascon_encryption_time / (iterations as u128)
    );
    println!(
        "Avg. ASCON Decryption Time: {}us",
        ascon_decryption_time / (iterations as u128)
    );
    println!("================== ASCON Test ENDED ======================");
}

fn generate_random_string(size: usize) -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
    let string = bytes.iter().map(|&c| c as char).collect::<String>();
    string
}
