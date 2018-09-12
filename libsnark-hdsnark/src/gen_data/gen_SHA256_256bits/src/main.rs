#![feature(rustc_private)]

extern crate rustc;
use rustc::util::sha2::{Digest,Sha256};
//use std::u8;

//use self::Test::*;

fn main() {
    println!("valid: ");
    let premium = gen();
    println!("\npremium = {}", premium);
    print!("premium = int_list_to_bits(");
    print!("{{");
    print!("{},", (premium & 65280)>>8);
    print!("{}", (premium & 255));
    println!("}}, 8);");
}

fn gen() -> u64{

    // std:shared_ptr<digest_variable<FieldT>> HB_var; /* Heartbeat         8 bits */
    // std::shared_ptr<digest_variable<FieldT>> BP_var; /* Blood Pressure(diastolic and systolic)  8+8 bits */
    // std::shared_ptr<digest_variable<FieldT>> H_var;  /* Height            8 bits */
    // std::shared_ptr<digest_variable<FieldT>> W_var;  /* Weight            8 bits */
    // std::shared_ptr<digest_variable<FieldT>> LC_var; /* Lung Capacity     16 bits */
    // std::shared_ptr<digest_variable<FieldT>> ID_var; /* ID                16 bits */
    // std::shared_ptr<digest_variable<FieldT>> T_var;  /* Time(yyyy/mm/dd)  12+4+8 bits */
    // std::shared_ptr<digest_variable<FieldT>> R_var;  /* RandomNumer       20*8 bits */
    
    // HB_var(80), BP_var(75, 115), H_var(178), W_var(85), LC_var(4500(17 148)), ID_var(45585(178, 17)), T_var((12+4+8) = 20180709(126, 39, 9), R_var(160)
    let r: Vec<u8> = vec![80, 75, 115, 178, 85, 17, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18];
    // r.push(80);

    let h: Vec<u8> = {
        let mut hash = Sha256::new();
        hash.input(&r);
        hash.result_bytes()
    };


    let mut hb_bv: Vec<u8> = vec![];
    hb_bv.push(r[0]);

    let mut bp_bv: Vec<u8> = vec![];
    for i in 1..3 {
        bp_bv.push(r[i]);
    }

    let mut h_bv: Vec<u8> = vec![];
    h_bv.push(r[3]);

    let mut w_bv: Vec<u8> = vec![];
    w_bv.push(r[4]);
    
    let mut lc_bv: Vec<u8> = vec![];
    for i in 5..7 {
        lc_bv.push(r[i]);
    }
    let mut ID_bv: Vec<u8> = vec![];
    for i in 7..9 {
        ID_bv.push(r[i]);
    }
    let mut t_bv: Vec<u8> = vec![];
    for i in 9..12 {
        t_bv.push(r[i]);
    }
    let mut r_bv: Vec<u8> = vec![];
    for i in 12..32 {
        r_bv.push(r[i]);
    }

    print!("h_data_bv = int_list_to_bits("); into_bin(&h);
    println!("");
    print!("// tuple_data_bv = int_list_to_bits("); into_bin(&r);
    print!("hb_bv = int_list_to_bits("); into_bin(&hb_bv);
    print!("bp_bv = int_list_to_bits("); into_bin(&bp_bv);
    print!("h_bv = int_list_to_bits("); into_bin(&h_bv);
    print!("w_bv = int_list_to_bits("); into_bin(&w_bv);
    print!("lc_bv = int_list_to_bits("); into_bin(&lc_bv);
    print!("ID_bv = int_list_to_bits("); into_bin(&ID_bv);
    print!("t_bv = int_list_to_bits("); into_bin(&t_bv);
    print!("r_bv = int_list_to_bits("); into_bin(&r_bv);


    // generate the coefficient
    let r_coeff: Vec<u8> = vec![8, 5, 10, 2, 2, 1, 148, 178, 17, 126, 39, 9, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18];
    // b.push_back(8);  // Heartbeat
    // b.push_back(5);  // Blood Pressure (diastolic)
    // b.push_back(10); // Blood Pressure (systolic)
    // b.push_back(2);  // Height
    // b.push_back(2);  // Weight   
    // b.push_back(1);  // Lung Capacity

    let hash_coeff: Vec<u8> = {
        let mut hash = Sha256::new();
        hash.input(&r_coeff);
        hash.result_bytes()
    };

    let mut hb_coeff_bv: Vec<u8> = vec![];
    hb_coeff_bv.push(r_coeff[0]);

    let mut bp_diastolic_coeff_bv: Vec<u8> = vec![];
    bp_diastolic_coeff_bv.push(r_coeff[1]);

    let mut bp_systolic_coeff_bv: Vec<u8> = vec![];
    bp_systolic_coeff_bv.push(r_coeff[2]);

    let mut h_coeff_bv: Vec<u8> = vec![];
    h_coeff_bv.push(r_coeff[3]);

    let mut w_coeff_bv: Vec<u8> = vec![];
    w_coeff_bv.push(r_coeff[4]);
    
    let mut lc_coeff_bv: Vec<u8> = vec![];
    lc_coeff_bv.push(r_coeff[5]);
    
    let mut r_coeff_bv: Vec<u8> = vec![];
    for i in 6..32 {
        r_coeff_bv.push(r_coeff[i]);
    }

    print!("\nhash_coeff_bv = int_list_to_bits("); into_bin(&hash_coeff);
    println!("");
    print!("// r_coeff_bv = int_list_to_bits("); into_bin(&r_coeff);
    print!("hb_coeff_bv = int_list_to_bits("); into_bin(&hb_coeff_bv);
    print!("bp_diastolic_coeff_bv = int_list_to_bits("); into_bin(&bp_diastolic_coeff_bv);
    print!("bp_systolic_coeff_bv = int_list_to_bits("); into_bin(&bp_systolic_coeff_bv);
    print!("h_coeff_bv = int_list_to_bits("); into_bin(&h_coeff_bv);
    print!("w_coeff_bv = int_list_to_bits("); into_bin(&w_coeff_bv);
    print!("lc_coeff_bv = int_list_to_bits("); into_bin(&lc_coeff_bv);
    print!("r_coeff_bv = int_list_to_bits("); into_bin(&r_coeff_bv);

    // compute premium
    let hb = hb_bv[0];
    let bp_d = bp_bv[0];
    let bp_s = bp_bv[1];
    let height = h_bv[0];
    let weight = w_bv[0];
    let lc: u16 = (lc_bv[0] as u16)*256 + (lc_bv[1] as u16);
    let ID: u16 = (ID_bv[0] as u16)*256 + (ID_bv[1] as u16);
    let time: u32 = ((((t_bv[0] as u32) & 240) >> 4)*256 + ((t_bv[0] as u32) & 15)*16 + (((t_bv[1] as u32) & 240) >> 4))*10000 + ((t_bv[1] as u32) & 15)*100 + (t_bv[2] as u32);
    
    println!("");
    println!("hb = {}", hb);
    println!("bp_d = {}", bp_d);
    println!("bp_s = {}", bp_s);
    println!("height = {}", height);
    println!("weight = {}", weight);
    println!("lc = {}", lc);
    println!("ID = {}", ID);
    println!("time = {}", time);

    let premium: u64;
    if time < 20180701 {
        return 0;
    }
    premium = (hb as u64) * 8 + (bp_d as u64) * 5 + (bp_s as u64) * 10 + (height as u64) * 2 + (weight as u64) * 2 + (lc as u64) * 1;
    return premium;
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



// #![feature(rustc_private)]

// extern crate rustc;
// use rustc::util::sha2::{Digest,Sha256};
// use std::u8;

// use self::Test::*;

// enum Test {
//     Valid,
//     AndInsteadOfXor
// }

// fn main() {
//     println!("valid: ");
//     gen(Valid);
//     println!("using AND instead of XOR: ");
//     gen(AndInsteadOfXor);
// }

// fn gen(test: Test) {
//     let r2: Vec<u8> = {
//         let mut hash = Sha256::new();
//         hash.input("SCIPR".as_ref());
//         hash.result_bytes()
//     };
//     let x: Vec<u8> = {
//         let mut hash = Sha256::new();
//         hash.input("LAB".as_ref());
//         hash.result_bytes()
//     };
//     let r1 = {
//         let mut v = vec![];
//         for (a, b) in r2.iter().zip(x.iter()) {
//             if let AndInsteadOfXor = test {
//                 v.push(a & b);
//             } else {
//                 v.push(a ^ b);
//             }
//         }

//         v
//     };

//     let h1: Vec<u8> = {
//         let mut hash = Sha256::new();
//         hash.input(&r1);
//         hash.result_bytes()
//     };

//     let h2: Vec<u8> = {
//         let mut hash = Sha256::new();
//         hash.input(&r2);
//         hash.result_bytes()
//     };

//     print!("h1_bv = int_list_to_bits("); into_bin(&h1);
//     print!("h2_bv = int_list_to_bits("); into_bin(&h2);
//     print!("x_bv = int_list_to_bits("); into_bin(&x);
//     print!("r1_bv = int_list_to_bits("); into_bin(&r1);
//     print!("r2_bv = int_list_to_bits("); into_bin(&r2);
// }

// fn into_bin(a: &Vec<u8>) {
//     let mut first = true;
//     print!("{{");
//     for a in a.iter() {
//         print!("{}{}",
//                 {if !first { ", " } else {first = false; ""}},
//                 a
//                 );
//     }
//     println!("}}, 8);");
// }
