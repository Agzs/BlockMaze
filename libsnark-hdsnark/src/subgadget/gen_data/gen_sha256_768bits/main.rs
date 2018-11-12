#![feature(rustc_private)]

extern crate rustc;
use rustc::util::sha2::{Digest,Sha256};
//use std::u8;

//use self::Test::*;

fn main() {
    println!("valid: ");
    gen();
}

fn gen() { 
    let r: Vec<u8> = vec![80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18, 
                          80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18, 
                          80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18];

    let h: Vec<u8> = {
        let mut hash = Sha256::new();
        hash.input(&r);
        hash.result_bytes()
    };

    print!("hash_bv = int_list_to_bits("); into_bin(&h);
    println!("");
    print!("tuple_data_bv = int_list_to_bits("); into_bin(&r);
}

fn into_bin(a: &Vec<u8>) {
    let mut first = true;
    print!("{{");
    for a in a.iter() {
        print!("{}{}",
                {if !first { ", " } else {first = false; ""}},
                a
                );
    }
    println!("}}, 8);");
}