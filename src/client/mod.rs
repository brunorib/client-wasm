extern crate rand;
extern crate base64;

use crate::commons::{AnswerInfo, CommitInfoPayload, CONCAT};

use uuid::Uuid;
use openssl::sha::Sha256;
use rand::Rng;
use rand::distributions::Alphanumeric;
use openssl::rsa::Rsa;
use openssl::pkey::{Public};
use openssl::bn::{BigNum, BigNumContext};

pub fn calculate_commit(amount: u32, k: u32, key: &Rsa<Public>) -> CommitInfoPayload {
    let mut answers: Vec<AnswerInfo> = Vec::new();
    let mut commits: Vec<String> = Vec::new();
    let n = key.n();
    let e = key.e();

    for _i in 0..k {
        let r: BigNum = generate_random_bytes(256);
        let alfa: String = generate_random_string(32);
        let beta: String = generate_random_string(32);
        let u: String = BigNum::from_u32(amount).unwrap().to_string() + CONCAT + &alfa;
        let id: Uuid = Uuid::new_v4();
        let v: String = id.to_string() + CONCAT + &beta;

        let mut hasher: Sha256 = Sha256::new();
        let to_hash: String = u.clone() + CONCAT + &v;
        
        hasher.update(&to_hash.as_bytes());

        let output_hash = BigNum::from_slice(&hasher.finish()).unwrap();

        let mut m: BigNum = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        m.mod_exp(&r, e, n, &mut ctx).unwrap();
        let mut m_mod: BigNum = BigNum::new().unwrap();
        m_mod.mod_mul(&m, &output_hash, n, &mut ctx).unwrap();

        let info: AnswerInfo = AnswerInfo {
            blinding: bignum_to_base64(r),
            amount: u, 
            id: v
        };
        answers.push(info);
        commits.push(bignum_to_base64(m_mod));
    }
    CommitInfoPayload {
        answers: answers,
        commits: commits,
    }
}

pub fn unblind_signature(blinded: &String, random: &String, key: &Rsa<Public>) -> String {
    let n = key.n();
    let b: BigNum = base64_to_bignum(blinded);
    let r: BigNum = base64_to_bignum(random);

    let mut ctx = BigNumContext::new().unwrap();

    let mut r_inverse: BigNum = BigNum::new().unwrap();
    r_inverse.mod_inverse(&r, n, &mut ctx).unwrap();

    let mut s: BigNum = BigNum::new().unwrap();
    s.mod_mul(&b, &r_inverse, n, &mut ctx).unwrap();

    bignum_to_base64(s)
}

fn generate_random_bytes(len: u32) -> BigNum {
    let bytes: Vec<u8> = (0..len).map(|_| { rand::random::<u8>() }).collect();
    BigNum::from_slice(&bytes).unwrap()
}

fn generate_random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .collect::<String>()
}

fn base64_to_bignum(base64: &String) -> BigNum {
    BigNum::from_slice(&base64::decode(base64).unwrap()).unwrap()
}

fn bignum_to_base64(num: BigNum) -> String {
    base64::encode(num.to_vec())
}