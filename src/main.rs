extern crate rand;
use rand::thread_rng;
use rand::distributions::{Distribution, Uniform};

extern crate base64;

//Takes input to encrypt in the form of a string and the key to encrypt with in the form of a base64 string. Generates a new 
//random key if one is not provided, and then returns the encrypted string and the key used.
fn encrypt(input: &String, key_option: Option<&String>) -> Result<(String, String), &'static str> {
    //Take input and convert to bytes
    let input_bytes = input.as_bytes();

    //Generate key if there isnt one
    let mut key = Vec::new();
    match key_option {
        Some(k) => key = match base64::decode(k) {
            Ok(i) if i.len() == input_bytes.len() => i,
            Ok(_) => { return Err("Key is not the same length as the input"); },
            Err(_) => { return Err("Key is not a valid base64 string"); },
        },
        None => {
            let mut rng = thread_rng();
            let range = Uniform::from(0..=255);
            for _ in 0..input_bytes.len() {
                key.push(range.sample(&mut rng));
            }
        },
    }

    //Encrypts
    let mut output_bytes = Vec::new();
    for i in 0..input_bytes.len() {
        output_bytes.push(input_bytes[i]^key[i]);
    } 
    Ok((base64::encode(output_bytes), base64::encode(key)))
}

//Takes input to decrypt in the form of a base64 string and the key to decrypt with in the form of a base64 string.
fn decrypt(input: &String, key: &String) -> Result<String, &'static str> {
    let key = match base64::decode(key) {
        Ok(i) => i,
        Err(_) => return Err("Key is not a valid base64 string"),
    };
    let input = match base64::decode(input) {
        Ok(i) => i,
        Err(_) => return Err("Key is not a valid base64 string"),
    };
    if input.len() != key.len() {
        return Err("Input and key are different lengths")
    }
    let mut output_bytes_2 = Vec::new();
    for i in 0..input.len() {
        output_bytes_2.push(input[i]^key[i]);
    } 
    Ok(String::from_utf8(output_bytes_2).unwrap_or("0".to_string()))
}

//Prints help
fn help() {
    println!("Encrypts and decrypts strings. Strings to encrypt are taken in a normal string format, and strings to decrypt are taken as raw bytes, in the form of base64");
    println!("Usage:");
    println!("crypto --help | crypto -h");
    println!("\tPrints this message");
    println!("crypto encrypt input | crypto encrypt input key");
    println!("\tEncrypts the input using the given key, or a random one if none is supplied. The key is printed along with the output.");
    println!("crypto decrypt input key");
    println!("\tDecrypts the input using the given key.");
}

fn main() {
    let args = std::env::args().collect::<Vec<String>>();

    let handler = |s| {println!("{}", s); std::process::exit(1)};
    let handler2 = |s| {println!("{}", s); std::process::exit(1)};

    match args.len() {
        1 => help(),
        2 => match args[1].as_str() {
            "--help" => help(),
            "-h" => help(),
            _ => help(),
        },
        3 => match args[1].as_str() {
            "encrypt" => {
                let (output, key) = encrypt(&args[2], None).unwrap_or_else(handler);
                println!("Output: {}", output);
                println!("Key: {}", key);
            },
            _ => help(),
        },
        4 => match args[1].as_str() {
            "encrypt" => {
                let (output, key) = encrypt(&args[2], Some(&args[3])).unwrap_or_else(handler);
                println!("Output: {}", output);
                println!("Key: {}", key);
            },
            "decrypt" => println!("{}", decrypt(&args[2], &args[3]).unwrap_or_else(handler2)),
            _ => help(),
        },
        _ => help(),
    }
}

#[cfg(test)]
mod tests {
    use crate::{encrypt, decrypt};
    #[test]
    fn with_key() {
        let test_val = String::from("1234567890");
        let key = base64::encode(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
        let encrypted = encrypt(&test_val, Some(&key)).unwrap().0;
        assert_eq!(test_val, decrypt(&encrypted, &key).unwrap());

        let test_val = String::from("hello");
        let key = base64::encode(vec![66, 45, 32, 45, 123]);
        let encrypted = encrypt(&test_val, Some(&key)).unwrap().0;
        assert_eq!(test_val, decrypt(&encrypted, &key).unwrap());

        let test_val = String::from("GOODBYE");
        let key = base64::encode(vec![255, 254, 253, 252, 251, 250, 249]);
        let encrypted = encrypt(&test_val, Some(&key)).unwrap().0;
        assert_eq!(test_val, decrypt(&encrypted, &key).unwrap());
    }
    //This is probabilistic as a random key is generated.
    #[test]
    fn without_key() {
        let test_val = String::from("1234567890");
        let (encrypted, key) = encrypt(&test_val, None).unwrap();
        assert_eq!(test_val, decrypt(&encrypted, &key).unwrap());
    
        let test_val = String::from("hello");
        let (encrypted, key) = encrypt(&test_val, None).unwrap();
        assert_eq!(test_val, decrypt(&encrypted, &key).unwrap());
    
        let test_val = String::from("GOODBYE");
        let (encrypted, key) = encrypt(&test_val, None).unwrap();
        assert_eq!(test_val, decrypt(&encrypted, &key).unwrap());
    }
    #[test]
    fn invalid_base_64() {
        let test_val = String::from("0");
        let key_invalid = String::from("12345");
        encrypt(&test_val, Some(&key_invalid)).unwrap_err();

        decrypt(&test_val, &key_invalid).unwrap_err();

        let test_val_base64 = String::from("hello");
        let key = base64::encode(vec![66, 45, 32, 45, 123]);
        decrypt(&test_val_base64, &key).unwrap_err();

    }
    #[test]
    fn different_length_inputs_and_keys() {
        let test_val = String::from("1234567890");
        let key = base64::encode(vec![66, 45, 32, 45, 123]);
        encrypt(&test_val, Some(&key)).unwrap_err();

        let test_val = String::from("hello");
        let key = base64::encode(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
        encrypt(&test_val, Some(&key)).unwrap_err();


        let test_val = String::from("1234567890");
        let key = base64::encode(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
        let encrypted = encrypt(&test_val, Some(&key)).unwrap().0;
        let long_key = base64::encode(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
        decrypt(&encrypted, &long_key).unwrap_err();
        let short_key = base64::encode(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        decrypt(&encrypted, &short_key).unwrap_err();
    }
}
