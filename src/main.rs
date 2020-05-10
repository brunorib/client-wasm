extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use std::env;
use std::fs;
use std::time::{Instant, Duration};
use reqwest::blocking::Client;
use reqwest::blocking::Response;
use hyper::header::{HeaderValue, HeaderMap, AUTHORIZATION};
use serde_json::{Map, Value, json};
use openssl::rsa::Rsa;
use openssl::pkey::{Public};
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::dangerous_unsafe_decode;

mod client;
mod cert_parser;
mod commons;

use crate::cert_parser::parse_x509;
use crate::commons::*;

const COMMITMENTS: &str = "/commitments";
const ANSWERS: &str = "/answers";
const BALANCES: &str = "/balances";
const LOGIN: &str = "/login";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    iat: u32,
    exp: u32
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let api = &args[1];
    let username = &args[2];
    let password = &args[3];
    let quantity: u32 = args[4].parse::<u32>().unwrap();
    let number_tokens: u32 = args[5].parse::<u32>().unwrap();
    let k: u32 = args[6].parse::<u32>().unwrap();
    let certificate_file = &args[7];
    let out_folder = &args[8];

    let mut create = true;
    if Path::new("stats.csv").exists() {
        create = false;
    }

    let mut stats_file = OpenOptions::new()
        .create_new(create)
        .write(true)
        .append(true)
        .open("stats.csv")
        .unwrap();

    fs::create_dir_all(out_folder)?;
    let pem = fs::read_to_string(certificate_file).unwrap();
    let key: Rsa<Public> = parse_x509(pem);

    let client: Client = reqwest::blocking::Client::new();

    let amount: u32 = quantity/number_tokens;

    let mut token = get_user_token(&client, &mut stats_file, api, username, password);

    let user_id = get_id_from_token(&token);

    ingress_money(&client, &mut stats_file, api, &token, quantity);

    for i in 0..number_tokens {
        let before = Instant::now();
        let mut info_payload: CommitInfoPayload =  client::calculate_commit(amount, k, &key);
        let after = Instant::now();

        println!("Time to generate (milis): {}", after.duration_since(before).as_millis());

        let req = get_commit_request(user_id, info_payload.commits);
        let mut res = make_post_request_token(&client, &mut stats_file, api, COMMITMENTS, &req, &token);

        while res.is_err() {
            token = get_user_token(&client, &mut stats_file, api, username, password);
            res = make_post_request_token(&client, &mut stats_file, api, COMMITMENTS, &req, &token);
        }
    
        let commit_response : CommitResponse = res.unwrap().json()?;
    
        let answer_to_save = info_payload.answers.remove(commit_response.to_exclude_answers);
        
        let req = get_answer_request(user_id, info_payload.answers);
        let mut res = make_post_request_token(&client, &mut stats_file, api, ANSWERS, &req, &token);

        while res.is_err() {
            token = get_user_token(&client, &mut stats_file, api, username, password);
            res = make_post_request_token(&client, &mut stats_file, api, ANSWERS, &req, &token);
        }
        
        let blind_sign : BlindSignature = res.unwrap().json()?;
        
        let token = Token {
            signature: client::unblind_signature(&blind_sign.blind_signature, &answer_to_save.blinding, &key),
            amount: answer_to_save.amount,
            id: answer_to_save.id
        };
    
        let filepath = out_folder.to_owned() + "/token_" + &user_id.to_string() + "_" + &i.to_string() + ".json";
        fs::write(filepath, &serde_json::to_string(&token)?.as_bytes()).expect("Unable to write file");
        
    }
   
    Ok(())
}

fn print_to_stats(file: &mut File, duration_request: Duration, request: &str, success: bool) {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let line = request.to_owned() + "," + &duration_request.as_millis().to_string() + "," + &success.to_string() + "," + &timestamp.as_millis().to_string();
    if let Err(e) = writeln!(file, "{}", line) {
        println!("Couldn't write to file: {}", e);
    }
}

fn get_ingress_request(quantity: u32) -> Value {
    let mut map = Map::new();

    let q = json!(quantity);
    map.insert("amount".to_string(), q);

    Value::Object(map)
}

fn get_token_request(user: &str, pass: &str) -> Value {
    let mut map = Map::new();

    map.insert("username".to_string(), Value::String(user.to_string()));
    map.insert("password".to_string(), Value::String(pass.to_string()));

    Value::Object(map)
}

fn get_answer_request(user_id: u32, answers: Vec<AnswerInfo>) -> Value {
    let mut map = Map::new();

    let u_id = json!(user_id);
    map.insert("user_id".to_string(), u_id);
    map.insert("answers".to_string(), serde_json::value::to_value(answers).unwrap());

    Value::Object(map)
}

fn get_commit_request(user_id: u32, commits: Vec<String>) -> Value {
    let mut map = Map::new();

    let u_id = json!(user_id);
    map.insert("user_id".to_string(), u_id);
    let commits_val = commits.into_iter().map(|i| Value::String(i)).collect();
    map.insert("commits".to_string(), Value::Array(commits_val));

    Value::Object(map)
}

fn get_user_token(client: &Client, stats_file: &mut File, api: &str, user: &str, pass: &str) -> String {
    let req = get_token_request(user, pass);

    let response = make_post_request(client, stats_file, api, LOGIN, &req);
    
    if response.is_err() {
        let err = response.unwrap_err();
        println!("{}", err);
        return "res.is_err".to_string()
    }

    let val : Value = response.unwrap().json().unwrap();

    let s = val["token"].to_string();
    s.replace("\"", "")
}

fn get_id_from_token(token: &str) -> u32 {
    let tokendata = dangerous_unsafe_decode::<Claims>(&token).unwrap();
    tokendata.claims.iss.parse::<u32>().unwrap()
}

fn ingress_money(client: &Client, stats_file: &mut File, api: &str, token: &str, quantity: u32) {
    let req = get_ingress_request(quantity);
    
    let put_endpoint = BALANCES.to_string() + "/" + &get_id_from_token(token).to_string();
    make_put_request_token(client, stats_file, api, &put_endpoint, req, token).unwrap();
}

fn make_post_request_token(client: &Client, stats_file: &mut File, api: &str, endpoint: &str, req: &Value, token: &str) -> Result<Response, String> {
    let mut headers = HeaderMap::new();
    if token != "" {
        headers.insert(AUTHORIZATION, HeaderValue::from_str(token).unwrap());
    }
    
    let balance_end_by_u = api.to_owned() + endpoint;
    
    let before = Instant::now();
    let res = client.post(&balance_end_by_u)
        .headers(headers)
        .json(&req)
        .send();
    let after = Instant::now();
    
    if res.is_err() {
        print_to_stats(stats_file, after.duration_since(before), endpoint, false);
        return Err("res is err".to_string());
    }

    let res: Response = res.unwrap();

    print_to_stats(stats_file, after.duration_since(before), endpoint, res.status().is_success());

    if !res.status().is_success() {
        if res.status() == 401 {
            println!("Renew token");
            
            return Err("renew".to_string());
        }
        println!("Status {}\n{}", res.status(), res.text().unwrap());
        return Err("not successfull status".to_string());
    }

    Ok(res)
}

fn make_put_request_token(client: &Client, stats_file: &mut File, api: &str, endpoint: &str, req: Value, token: &str) -> Result<Response, String> {
    let mut headers = HeaderMap::new();
    if token != "" {
        headers.insert(AUTHORIZATION, HeaderValue::from_str(token).unwrap());
    }
    
    let balance_end_by_u = api.to_owned() + endpoint;
    
    let before = Instant::now();
    let res = client.put(&balance_end_by_u)
        .headers(headers)
        .json(&req)
        .send();
    let after = Instant::now();
    
    if res.is_err() {
        print_to_stats(stats_file, after.duration_since(before), endpoint, false);
        return Err("res is err".to_string());
    }

    let res = res.unwrap();

    print_to_stats(stats_file, after.duration_since(before), endpoint, res.status().is_success());

    if !res.status().is_success() {
        if res.status() == 401 {
            println!("Renew token");
            
            return Err("renew".to_string());
        }
        println!("Status {}\n{}", res.status(), res.text().unwrap());
        return Err("not successfull status".to_string());
    }

    Ok(res)
}


fn make_post_request(client: &Client, stats_file: &mut File, api: &str, endpoint: &str, req: &Value) -> Result<Response, String> {
    make_post_request_token(client, stats_file, api, endpoint, req, "")
}