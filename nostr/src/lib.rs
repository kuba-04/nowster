use std::io;
use std::ops::Add;
use nostr_sdk::prelude::StreamExt;
use nostr_sdk::{Client, Filter, Keys, Kind, Timestamp};
use std::time::Duration;

pub async fn run_nostr(decrypted_key: String) {
    let client = connect_to_nostr(decrypted_key.as_str()).await;
    let until = fetch_events(&client, None).await;
    let mut until = until.add(Duration::from_millis(1));

    loop {
        let mut command = String::new();
        let _ = io::stdin().read_line(&mut command);

        if command.trim().is_empty() || command.trim_end_matches(&['\r', '\n'][..]).is_empty() {
            until = fetch_events(&client, Some(until)).await;
        } else if command.trim().eq_ignore_ascii_case("q") {
            println!("bye!");
            break;
        } else {
            eprintln!("Error exit. Entered: {}", command.trim());
            break;
        }
    }
}

async fn fetch_events(client: &Client, timestamp: Option<Timestamp>) -> Timestamp {
    let mut filter = Filter::new().kind(Kind::TextNote).limit(5);
    if let Some(ts) = timestamp {
        filter = filter.clone().until(ts.add(Duration::from_nanos(1)));
    }
    let mut stream = client.stream_events(filter, Duration::from_secs(5)).await.unwrap();

    let mut last_event_ts = Timestamp::now();

    while let Some(event) = stream.next().await {
        last_event_ts = event.created_at;
        println!("{}", event.content);
        println!("-------------");
        println!();
    }
    last_event_ts
}

async fn connect_to_nostr(priv_key: &str) -> Client {
    let keys = Keys::parse(priv_key);
    let client = Client::new(keys.unwrap());

    let _ = client.add_relay("wss://relay.damus.io").await;
    client.connect().await;
    client
}

pub fn derive_pubkey(priv_key: &str) -> String {
    let keys = Keys::parse(priv_key);
    keys.expect("Failed to parse keys").public_key.to_string()
}