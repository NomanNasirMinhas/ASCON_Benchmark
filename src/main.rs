extern crate core;
extern crate rand;
extern crate systemstat;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use ascon_aead::Ascon128;
use chacha20poly1305::ChaCha20Poly1305;
use csv;
use hc_256::cipher::{KeyIvInit, StreamCipher};
use hc_256::Hc256;
use mosquitto_rs::{Client, Error, QoS};
use openssl::symm::{decrypt, encrypt, Cipher};
use rand::Rng;
use std::io;
use std::thread;

// use std::time::{Duration, Instant};
use dhat;
use std::{mem, time::Instant};
use systemstat::{saturating_sub_bytes, Duration, Platform, System};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[tokio::main]
async fn main() {
    // let mut memgetMemoryUsed();
    let mut encryption_times = Vec::new();
    let mut decryption_times = Vec::new();

    let mut iterations = String::new();
    let mut string_size = String::new();
    let mut test_type = String::new();
    let stdin = io::stdin();
    println!("********************************************************************");
    println!("Select the Algorithm You Want to Benchmark");
    println!("1. AES");
    println!("2. 3DES");
    println!("3. ChaCha20");
    println!("4. HC256");
    println!("5. ASCON");
    println!("********************************************************************");
    stdin.read_line(&mut test_type);
    let test_type: u32 = test_type.trim().parse().expect("Please enter a number");
    println!("Enter the number of iterations you want to run: ");
    stdin.read_line(&mut iterations);
    let iterations: u32 = iterations.trim().parse().expect("Please enter a number");
    println!("Enter the minimum size (bytes) of the payload you want to encrypt: ");
    stdin.read_line(&mut string_size);
    let string_size: usize = string_size.trim().parse().expect("Please enter a number");
    let msg = generate_random_string(string_size);
    let msg = msg.as_str();
    println!("Payload Generated of {} bytes....", msg.len());
    println!(
        "Starting Test for {} Iterations and {} bytes of payload ",
        iterations,
        msg.len()
    );
    println!();
    // let mut client = Client::with_auto_id().unwrap();

    // let rc = client
    //     .connect("localhost", 1883, std::time::Duration::from_secs(5), None)
    //     .await
    //     .unwrap();
    // println!("Connected To Mosquitto Broker: {}", rc);

    // let subscriptions = client.subscriber().unwrap();

    // client.subscribe("test", QoS::AtMostOnce).await.unwrap();
    // println!("Subscribed to Topic: test");

    // let msg = "Hello World! This is a test message. We are testing different encryption algorithms.
    // This is a test message. We are testing different encryption algorithms. This is a test message.";
    if (test_type == 1) {
        println!();
        println!("================== AES Test STARTED ======================");
        //AES Test Start
        let aes_key = Aes256Gcm::generate_key(OsRng);
        let mut aes_encryption_time = 0;
        let mut aes_decryption_time = 0;
        for _ in 0..iterations {
            // wait for a second
            // thread::sleep(Duration::from_secs(1));
            print!(".");
            let cipher = Aes256Gcm::new(&aes_key);
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let start = Instant::now();
            let aes_ciphertext = cipher.encrypt(&nonce, msg.as_bytes()).unwrap();
            let elapsed = start.elapsed();
            encryption_times.push(elapsed.as_micros());
            aes_encryption_time += elapsed.as_micros();
            // client
            //     .publish("test", aes_ciphertext.as_slice(), QoS::AtMostOnce, false)
            //     .await
            //     .unwrap();
            // println!("AES published. It took {}us to encrypt and send {} bytes of data", elapsed.as_micros(), msg.len());

            // if let Ok(msg) = subscriptions.recv().await {
            let start = Instant::now();
            let plaintext = cipher.decrypt(&nonce, aes_ciphertext.as_slice()).unwrap();
            let elapsed = start.elapsed();
            decryption_times.push(elapsed.as_micros());
            aes_decryption_time += elapsed.as_micros();
            let plaintext = std::str::from_utf8(&plaintext).unwrap();
            // println!("AES Received. It took {}us to decrypt {} bytes of data", elapsed.as_micros(), plaintext.len());
            // }
            //Wait for half second
            thread::sleep(Duration::from_millis(200));
        }
        // println!();
        println!();
        println!(
            "Avg. AES Encryption Time: {}us",
            aes_encryption_time / (iterations as u128)
        );
        println!();
        println!(
            "Avg. AES Decryption Time: {}us",
            aes_decryption_time / (iterations as u128)
        );
        println!("================== AES Test ENDED ======================");
    }

    if (test_type == 2) {
        println!();
        println!("================== 3DES Test START ======================");
        let mut des_encryption_time = 0;
        let mut des_decryption_time = 0;
        for _ in 0..iterations {
            // wait for a second
            // thread::sleep(Duration::from_secs(1));
            print!(".");
            let des_string = "0123456789987654gdsg3210".as_bytes()[0..24].to_vec();
            let cipher = Cipher::des_ede3_cbc();
            let start = Instant::now();
            let des_ciphertext =
                encrypt(cipher, des_string.as_slice(), None, msg.as_bytes()).unwrap();
            let elapsed = start.elapsed();
            encryption_times.push(elapsed.as_micros());
            des_encryption_time += elapsed.as_micros();
            // client
            //     .publish("test", des_ciphertext.as_slice(), QoS::AtMostOnce, false)
            //     .await
            //     .unwrap();
            // println!("DES published. It took {}us to encrypt and send {} bytes of data", elapsed.as_micros(), msg.len());
            // if let Ok(msg) = subscriptions.recv().await {
            let start = Instant::now();
            let plaintext = decrypt(
                cipher,
                des_string.as_slice(),
                None,
                des_ciphertext.as_slice(),
            )
            .expect("Error decrypting DES");
            let elapsed = start.elapsed();
            decryption_times.push(elapsed.as_micros());
            des_decryption_time += elapsed.as_micros();
            let plaintext = std::str::from_utf8(&plaintext).unwrap();
            thread::sleep(Duration::from_millis(200));

            // println!("DES Received. It took {}us to decrypt {} bytes of data", elapsed.as_micros(), plaintext.len());
            // }
        }
        // println!();
        println!();
        println!(
            "Avg. 3DES Encryption Time: {}us",
            des_encryption_time / (iterations as u128)
        );
        println!();
        println!(
            "Avg. 3DES Decryption Time: {}us",
            des_decryption_time / (iterations as u128)
        );
        println!("================== 3DES Test ENDED ======================");
    }

    if (test_type == 3) {
        println!();
        println!("================== ChaCha20 Test START ======================");
        let mut chacha_encryption_time = 0;
        let mut chacha_decryption_time = 0;
        for _ in 0..iterations {
            // wait for a second
            // thread::sleep(Duration::from_secs(1));
            print!(".");
            let key = ChaCha20Poly1305::generate_key(&mut OsRng);
            let cipher = ChaCha20Poly1305::new(&key);
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let start = Instant::now();
            let chacha_ciphertext = cipher.encrypt(&nonce, msg.as_bytes()).unwrap();
            let elapsed = start.elapsed();
            encryption_times.push(elapsed.as_micros());
            chacha_encryption_time += elapsed.as_micros();
            // client
            //     .publish("test", chacha_ciphertext.as_slice(), QoS::AtMostOnce, false)
            //     .await
            //     .unwrap();
            // println!("ChaCha20 published. It took {}us to encrypt and send {} bytes of data", elapsed.as_micros(), msg.len());
            // if let Ok(msg) = subscriptions.recv().await {
            let start = Instant::now();
            let plaintext = cipher
                .decrypt(&nonce, chacha_ciphertext.as_slice())
                .unwrap();
            let elapsed = start.elapsed();
            decryption_times.push(elapsed.as_micros());
            chacha_decryption_time += elapsed.as_micros();
            let plaintext = std::str::from_utf8(&plaintext).unwrap();
            thread::sleep(Duration::from_millis(200));

            // println!("ChaCha20 Received. It took {}us to decrypt {} bytes of data", elapsed.as_micros(), plaintext.len());
            // }
        }
        // println!();
        println!();
        println!(
            "Avg. ChaCha20 Encryption Time: {}us",
            chacha_encryption_time / (iterations as u128)
        );
        println!();
        println!(
            "Avg. ChaCha20 Decryption Time: {}us",
            chacha_decryption_time / (iterations as u128)
        );
        println!("================== ChaCha20 Test ENDED ======================");
    }

    if (test_type == 4) {
        println!();
        println!("================== HC256 Test START ======================");
        let mut hc256_encryption_time = 0;
        let mut hc256_decryption_time = 0;
        for _ in 0..iterations {
            // wait for a second
            // thread::sleep(Duration::from_secs(1));
            print!(".");
            let key = [0x42; 32];
            let nonce = [0x24; 32];
            let mut cipher = Hc256::new(&key.into(), &nonce.into());
            let mut buffer = msg.clone().as_bytes();
            let start = Instant::now();
            cipher.apply_keystream(&mut buffer.to_owned());
            let elapsed = start.elapsed();
            encryption_times.push(elapsed.as_micros());
            hc256_encryption_time += elapsed.as_micros();
            // client
            //     .publish("test", buffer, QoS::AtMostOnce, false)
            //     .await
            //     .unwrap();
            // println!("HC256 published. It took {}us to encrypt and send {} bytes of data", elapsed.as_micros(), msg.len());
            // if let Ok(msg) = subscriptions.recv().await {
            let mut cipher = Hc256::new(&key.into(), &nonce.into());
            let mut mesg = buffer.as_ref();
            let start = Instant::now();
            cipher.apply_keystream(&mut mesg.to_owned());
            let elapsed = start.elapsed();
            decryption_times.push(elapsed.as_micros());
            hc256_decryption_time += elapsed.as_micros();
            let plaintext = std::str::from_utf8(&mesg).unwrap();
            thread::sleep(Duration::from_millis(200));

            // println!("HC256 Received. It took {}us to decrypt {} bytes of data", elapsed.as_micros(), plaintext.len());
            // }
        }
        // println!();
        println!();
        println!(
            "Avg. HC256 Encryption Time: {}us",
            hc256_encryption_time / (iterations as u128)
        );
        println!();
        println!(
            "Avg. HC256 Decryption Time: {}us",
            hc256_decryption_time / (iterations as u128)
        );
        println!("================== HC256 Test ENDED ======================");
    }

    if (test_type == 5) {
        println!();
        println!("================== ASCON Test START ======================");
        let mut ascon_encryption_time = 0;
        let mut ascon_decryption_time = 0;
        for _ in 0..iterations {
            // wait for a second
            // thread::sleep(Duration::from_secs(1));
            print!(".");
            let key = Key::<Ascon128>::from_slice(b"very secret key.");
            let cipher = Ascon128::new(key);
            let nonce = ascon_aead::Nonce::<Ascon128>::from_slice(b"unique nonce 012");
            let start = Instant::now();
            let ascon_ciphertext = cipher
                .encrypt(nonce, msg.as_bytes())
                .expect("encryption failure!");
            let elapsed = start.elapsed();
            encryption_times.push(elapsed.as_micros());
            ascon_encryption_time += elapsed.as_micros();
            // client
            //     .publish("test", ascon_ciphertext.as_slice(), QoS::AtMostOnce, false)
            //     .await
            //     .unwrap();
            // println!("ASCON published. It took {}us to encrypt and send {} bytes of data", elapsed.as_micros(), msg.len());
            // if let Ok(msg) = subscriptions.recv().await {
            let start = Instant::now();
            let plaintext = cipher
                .decrypt(nonce, ascon_ciphertext.as_slice())
                .expect("decryption failure!");
            let elapsed = start.elapsed();
            decryption_times.push(elapsed.as_micros());
            ascon_decryption_time += elapsed.as_micros();
            let plaintext = std::str::from_utf8(&plaintext).unwrap();
            thread::sleep(Duration::from_millis(200));

            // println!("ASCON Received. It took {}us to decrypt {} bytes of data", elapsed.as_micros(), plaintext.len());
            // }
        }
        println!();
        println!(
            "Avg. ASCON Encryption Time: {}us",
            ascon_encryption_time / (iterations as u128)
        );
        println!();
        println!(
            "Avg. ASCON Decryption Time: {}us",
            ascon_decryption_time / (iterations as u128)
        );
        println!("================== ASCON Test ENDED ======================");
    }

    // Output encryption and decryption times to csv
    let benchmark_name = match test_type {
        1 => "AES",
        2 => "3DES",
        3 => "ChaCha20",
        4 => "HC256",
        5 => "ASCON",
        _ => "Unknown",
    };
    let mut wtr =
        csv::Writer::from_path(format!("{}_encryption_times.csv", benchmark_name)).unwrap();
    for time in encryption_times {
        wtr.write_record(&[time.to_string()]).unwrap();
    }
    wtr.flush().unwrap();
    let mut wtr =
        csv::Writer::from_path(format!("{}_decryption_times.csv", benchmark_name)).unwrap();
    for time in decryption_times {
        wtr.write_record(&[time.to_string()]).unwrap();
    }
    wtr.flush().unwrap();
}

fn generate_random_string(size: usize) -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
    let string = bytes.iter().map(|&c| c as char).collect::<String>();
    // Clip to match exactly the number of bytes as size
    string[0..size].to_string()

}

fn getMemoryUsed() -> u64 {
    let sys = System::new();

    match sys.memory() {
        Ok(mem) => {
            println!(
                "\nMemory: {} used / {} ({} bytes) total ({:?})",
                saturating_sub_bytes(mem.total, mem.free),
                mem.total,
                mem.total.as_u64(),
                mem.platform_memory
            );
            return mem.total.as_u64();
        }
        Err(x) => {
            println!("\nMemory: error: {}", x);
            return 0 as u64;
        }
    }
}
