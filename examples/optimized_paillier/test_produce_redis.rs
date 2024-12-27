use redis::{Commands, Connection, RedisResult};

fn main() -> RedisResult<()> {
    // Connect to Redis
    let client = redis::Client::open("redis://127.0.0.1/")?;
    let mut con = client.get_connection()?;

    // Push messages to the Redis stream
    for i in 1..=10 {
        let message = format!("message_{}", i);
        let _: () = con.xadd("test", "*", &[("data", &message)])?;
        println!("Produced: {}", message);
    }

    Ok(())
}
