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
    let v: Vec<u8> = vec![3, 0, 0, 0, 0, 0, 0, 0];
    let sn: Vec<u8> = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let r: Vec<u8> = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let h: Vec<u8> = {
        let mut hash = Sha256::new();
        hash.input(&v);
        hash.input(&sn);
        hash.input(&r);
        hash.result_bytes()
    };

    print!("hash_bv = int_list_to_bits("); into_bin(&h);
    print!("v_data_bv = int_list_to_bits("); into_bin(&v);
    print!("sn_data_bv = int_list_to_bits("); into_bin(&sn);
    print!("r_data_bv = int_list_to_bits("); into_bin(&r);
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