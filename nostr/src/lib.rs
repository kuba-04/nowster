use nostr_sdk::prelude::StreamExt;
use nostr_sdk::{Client, Filter, Keys, Kind};
use std::time::Duration;

pub async fn fetch_events(priv_key: &str) {
    let keys = Keys::parse(priv_key);
    let client = Client::new(keys.unwrap());

    let _ = client.add_relay("wss://relay.damus.io").await;
    client.connect().await;
    //
    // for event in client.fetch_events(Filter::new(), Duration::new(5, 0)).await.unwrap() {
    //     println!("{:?}", event.content.as_str());
    // }

    let filter = Filter::new().kind(Kind::TextNote).limit(5);
    let mut stream = client.stream_events(filter, Duration::from_secs(10)).await.unwrap();

    while let Some(event) = stream.next().await {
        println!("{}", event.content);
        println!("-------------")
    }
}

pub fn derive_pubkey(priv_key: &str) -> String {
    let keys = Keys::parse(priv_key);
    keys.expect("Failed to parse keys").public_key.to_string()
}