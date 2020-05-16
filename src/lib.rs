#![feature(test)]

extern crate test;
extern crate bigi_ecc;

use rand;
use sha2::{Sha256, Digest};
use bigi:: Bigi;
use bigi_ecc::{Point};
use bigi_ecc::schemas;
use bigi_ecc::elgamal;
use bigi_ecc::ecdsa;
use bigi_ecc::mapping::Mapper;
use wasm_bindgen::prelude::*;

const HASH_STORAGE_BITS: usize = 256;

mod utils;
use utils::*;


#[wasm_bindgen]
pub fn get_private_key(secret: &str) -> String {
    let schema = schemas::load_secp256k1();
    let z = {
        let mut z = Bigi::from_bytes(secret.as_bytes());
        z = z.powmod(&z, &schema.order);
        z
    };
    let p = schema.get_point(&z);
    hex_from_bigi(&p.x)
}


#[wasm_bindgen]
pub fn get_public_key(private_key: &str) -> String {
    let schema = schemas::load_secp256k1();
    let x = hex_to_bigi(private_key);
    let h = schema.get_point(&x);
    hex_from_point(&h)
}


#[wasm_bindgen]
pub fn check_keys(private_key: &str, public_key: &str) -> bool {
    let x = hex_to_bigi(private_key);
    let h = hex_to_point(public_key);
    let schema = schemas::load_secp256k1();
    schema.get_point(&x) == h
}


#[wasm_bindgen]
pub fn encrypt(public_key: &str, body: &str) -> String {
    let h = hex_to_point(public_key);

    let mut rng = rand::thread_rng();
    let schema = schemas::load_secp256k1();

    let mapper = Mapper::new(HASH_STORAGE_BITS, &schema.curve);
    let points = mapper.pack(&body.as_bytes().to_vec());

    let (c1, c2) = elgamal::encrypt(&mut rng, &schema, &h, &points);

    hex_from_point(&c1) + &hex_from_point_vec(&c2)
}


#[wasm_bindgen]
pub fn decrypt(private_key: &str, block: &str) -> String {
    let x = hex_to_bigi(private_key);

    let c1c2: Vec<Point> = hex_to_point_vec(&block);

    let c1 = c1c2[0];
    let c2 = c1c2[1..].to_vec();

    let schema = schemas::load_secp256k1();
    let mapper = Mapper::new(HASH_STORAGE_BITS, &schema.curve);

    let points = elgamal::decrypt(&schema, &x, &(c1, c2));
    let bytes = mapper.unpack(&points);

    String::from_utf8(bytes).unwrap()
}


#[wasm_bindgen]
pub fn build_signature(private_key: &str, key: &str, block: &str) -> String {
    let x = hex_to_bigi(private_key);

    let mut rng = rand::thread_rng();
    let schema = schemas::load_secp256k1();

    let hash = {
        let mut hasher = Sha256::new();
        hasher.input(key);
        hasher.input(block);
        hasher.result().to_vec()
    };

    let s = ecdsa::build_signature(&mut rng, &schema, &x, &hash);

    hex_from_bigi_pair(&s)
}


#[wasm_bindgen]
pub fn check_signature(public_key: &str, key: &str, block: &str, signature: &str) -> bool {
    let s = hex_to_bigi_pair(signature);
    let h = hex_to_point(public_key);

    let schema = schemas::load_secp256k1();

    let hash = {
        let mut hasher = Sha256::new();
        hasher.input(key);
        hasher.input(block);
        hasher.result().to_vec()
    };

    ecdsa::check_signature(&schema, &h, &hash, &s)
}


#[wasm_bindgen]
pub fn build_secret_signature(private_key: &str, secret: &str) -> String {
    let x = hex_to_bigi(private_key);
    let mut rng = rand::thread_rng();
    let schema = schemas::load_secp256k1();
    let s = ecdsa::build_signature(&mut rng, &schema, &x, &hex_to_bytes(secret));
    hex_from_bigi_pair(&s)
}


#[wasm_bindgen]
pub fn check_secret_signature(public_key: &str, secret: &str, secret_signature: &str) -> bool {
    let s = hex_to_bigi_pair(secret_signature);
    let h = hex_to_point(public_key);
    let schema = schemas::load_secp256k1();
    ecdsa::check_signature(&schema, &h, &hex_to_bytes(secret), &s)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_private_key() {
        assert_eq!(
            get_private_key("alex:1234567"),
            "12BEC995D37D5267AD734B5B63FFFF048A511F71CD086D3E212FF13C9A037FD1"
        );
    }

    #[test]
    fn test_get_public_key() {
        assert_eq!(
            get_public_key("12BEC995D37D5267AD734B5B63FFFF048A511F71CD086D3E212FF13C9A037FD1"),
            "9F12C869D6330074C913C9D547946C5AA0DC9180F55CC001FDD06FAE3D281011FA32C6A14C56180C654E2224B6DB0A5B738736D59E9036254F41D32C7BF9C825"
        );
    }

    #[test]
    fn test_check_keys() {
        assert_eq!(
            check_keys(
                "12BEC995D37D5267AD734B5B63FFFF048A511F71CD086D3E212FF13C9A037FD1",
                "9F12C869D6330074C913C9D547946C5AA0DC9180F55CC001FDD06FAE3D281011FA32C6A14C56180C654E2224B6DB0A5B738736D59E9036254F41D32C7BF9C825"
            ), true
        );
    }

    #[test]
    fn test_encryption() {
        let private_key = "12BEC995D37D5267AD734B5B63FFFF048A511F71CD086D3E212FF13C9A037FD1";
        let public_key = "9F12C869D6330074C913C9D547946C5AA0DC9180F55CC001FDD06FAE3D281011FA32C6A14C56180C654E2224B6DB0A5B738736D59E9036254F41D32C7BF9C825";
        let body = "Some text.";
        let encrypted = encrypt(&public_key, &body);
        let decrypted = decrypt(&private_key, &encrypted);
        assert_eq!(decrypted, body);
    }

    #[test]
    fn test_signature() {
        let private_key = "12BEC995D37D5267AD734B5B63FFFF048A511F71CD086D3E212FF13C9A037FD1";
        let public_key = "9F12C869D6330074C913C9D547946C5AA0DC9180F55CC001FDD06FAE3D281011FA32C6A14C56180C654E2224B6DB0A5B738736D59E9036254F41D32C7BF9C825";
        let data_key = "Data key";
        let data_block = "Data block";
        let signature = build_signature(&private_key, &data_key, &data_block);
        assert_eq!(check_signature(&public_key, &data_key, &data_block, &signature), true);
    }

    #[test]
    fn test_secret_signature() {
        let private_key = "12BEC995D37D5267AD734B5B63FFFF048A511F71CD086D3E212FF13C9A037FD1";
        let public_key = "9F12C869D6330074C913C9D547946C5AA0DC9180F55CC001FDD06FAE3D281011FA32C6A14C56180C654E2224B6DB0A5B738736D59E9036254F41D32C7BF9C825";
        let secret = "D906DC161380BF7199872C62C24B5488BEEB4D27EA3F6D3E9E5619A460FF2DB1";
        let secret_signature = build_secret_signature(&private_key, &secret);
        assert_eq!(check_secret_signature(&public_key, &secret, &secret_signature), true);
    }
}
