use serde::Serialize;
use serde_json::{self, Value, Map};
use std::io::{Read, Write};
use std::fs::{File, OpenOptions};

use once_cell::sync::Lazy;
use redis::{Client, Commands, Connection, RedisResult};

static REDIS_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::open("redis://127.0.0.1/").expect("Failed to create Redis client")
});

pub fn get_redis_connection() -> RedisResult<Connection> {
    REDIS_CLIENT.get_connection()
}

#[derive(Serialize)] // Make the struct serializable to JSON
pub struct OutputData {
    pub benchmark_time: usize,
    pub benchmark_case: String,
    pub benchmark_params: String,
    pub precompute_table_block_size: usize
}

pub struct Logger {}

impl Logger {
    pub fn log_benchmark_time(output: OutputData , file_path: String) {
        let mut redis_client = get_redis_connection();
        if let Ok(mut con) = redis_client {
            let _ : () = con.xadd("test", "*", &[("data", serde_json::to_string(&output).unwrap().as_str())]).unwrap();
        } else {
            eprintln!("Failed to connect to Redis.");
        }
        let mut current_json = Map::new();
        if let Ok(mut file) = File::open(file_path.clone()) {
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap_or_default();
            current_json = serde_json::from_str(&contents).unwrap_or_else(|_| {
                let mut map = Map::new();
                map.insert("results".to_string(), Value::Array(vec![]));
                map
            });
        } else {
            current_json.insert("results".to_string(), Value::Array(vec![]));
        }

        if let Some(results) = current_json.get_mut("results").and_then(Value::as_array_mut) {
            results.push(serde_json::to_value(output).unwrap());
        }

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file_path)
        {
            if let Err(e) = file.write_all(serde_json::to_string_pretty(&current_json).unwrap().as_bytes()) {
                eprintln!("Failed to write to file: {:?}", e);
            }
        } else {
            eprintln!("Failed to open or create file for writing.");
        }

    }
}