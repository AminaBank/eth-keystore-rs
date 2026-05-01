use eth_keystore::{decrypt_key, encrypt_key, new};
use hex::FromHex;
use std::path::Path;

mod tests {
    use std::{
        fs::File,
        io::{Seek, SeekFrom},
    };

    use eth_keystore::{decrypt_key_from_reader, encrypt_key_with_writer, new_with_writer};

    use super::*;

    #[test]
    fn test_new() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::rng();
        let (secret, id) = new(dir, &mut rng, "thebestrandompassword", None).unwrap();

        let keypath = dir.join(&id);

        assert_eq!(
            decrypt_key(&keypath, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(decrypt_key(&keypath, "notthebestrandompassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_new_with_name() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::rng();
        let name = "my_keystore";
        let (secret, _id) = new(dir, &mut rng, "thebestrandompassword", Some(name)).unwrap();

        let keypath = dir.join(name);

        assert_eq!(
            decrypt_key(&keypath, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_new_with_writer() {
        let dir = Path::new("./tests/test-keys");
        let keystore = dir.join(format!("my-keystore_{}.json", rand::random::<u64>()));
        let mut keystore_file = File::create_new(&keystore).unwrap();

        let mut rng = rand::rng();
        let secret =
            new_with_writer(&mut keystore_file, &mut rng, "thebestrandompassword").unwrap();

        // reset cursor
        keystore_file.seek(SeekFrom::Start(0)).unwrap();

        assert_eq!(
            decrypt_key_from_reader(&mut keystore_file, "thebestrandompassword").unwrap(),
            secret
        );
        // reset cursor
        keystore_file.seek(SeekFrom::Start(0)).unwrap();
        assert!(decrypt_key_from_reader(&mut keystore_file, "notthebestrandompassword").is_err());
        assert!(std::fs::remove_file(&keystore).is_ok());
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_decrypt_pbkdf2() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-pbkdf2.json");
        assert_eq!(decrypt_key(keypath, "testpassword").unwrap(), secret);
        assert!(decrypt_key(keypath, "wrongtestpassword").is_err());
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_decrypt_pbkdf2_with_reader() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-pbkdf2.json");
        let mut keystore_file = File::open(keypath).unwrap();
        assert_eq!(
            decrypt_key_from_reader(&mut keystore_file, "testpassword").unwrap(),
            secret
        );
        // reset cursor
        keystore_file.seek(SeekFrom::Start(0)).unwrap();
        assert!(decrypt_key_from_reader(&mut keystore_file, "wrongtestpassword").is_err());
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_decrypt_scrypt() {
        let secret =
            Vec::from_hex("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-scrypt.json");
        assert_eq!(decrypt_key(keypath, "grOQ8QDnGHvpYJf").unwrap(), secret);
        assert!(decrypt_key(keypath, "thisisnotrandom").is_err());
    }

    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_decrypt_scrypt_with_reader() {
        let secret =
            Vec::from_hex("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-scrypt.json");
        let mut keystore_file = File::open(keypath).unwrap();
        assert_eq!(
            decrypt_key_from_reader(&mut keystore_file, "grOQ8QDnGHvpYJf").unwrap(),
            secret
        );
        // reset cursor
        keystore_file.seek(SeekFrom::Start(0)).unwrap();
        assert!(decrypt_key_from_reader(&mut keystore_file, "thisisnotrandom").is_err());
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::rng();
        let name = encrypt_key(dir, &mut rng, &secret, "newpassword", None).unwrap();

        let keypath = dir.join(&name);
        assert_eq!(decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_key_with_reader_and_writer() {
        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let dir = Path::new("./tests/test-keys");
        let keystore = dir.join(format!("my-keystore_{}.json", rand::random::<u64>()));
        let mut keystore_file = File::create_new(&keystore).unwrap();

        let mut rng = rand::rng();
        encrypt_key_with_writer(&mut keystore_file, &mut rng, &secret, "newpassword").unwrap();

        // reset cursor
        keystore_file.seek(SeekFrom::Start(0)).unwrap();

        assert_eq!(
            decrypt_key_from_reader(&mut keystore_file, "newpassword").unwrap(),
            secret
        );
        // reset cursor
        keystore_file.seek(SeekFrom::Start(0)).unwrap();
        assert!(decrypt_key_from_reader(&mut keystore_file, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keystore).is_ok());
    }
}
