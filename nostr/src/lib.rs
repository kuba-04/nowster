use nostr_sdk::prelude::StreamExt;
use nostr_sdk::{Client, Filter, Keys, Kind, PublicKey, TagKind, Timestamp};
use std::io;
use std::ops::Add;
use std::time::Duration;

pub async fn run_nostr(priv_key: Option<String>, pubkey: String) {
    println!("=======");
    let mut client = connect_to_nostr(priv_key).await;
    let pubkey = PublicKey::parse(pubkey.as_str()).expect("Failed to parse pubkey");
    let filter = Filter::new().author(pubkey).kind(Kind::ContactList);

    let mut follow_events = client.fetch_events(filter, Duration::from_secs(15)).await.unwrap().to_vec();
    if follow_events.is_empty() {
        println!("Follows not found");
        return;
    }

    let follow_list= follow_events
        .first()
        .unwrap().tags.iter()
        .filter(|tk| tk.kind().eq(&TagKind::p())).map(|t| t.content().unwrap())
        .map(|pk| PublicKey::parse(pk).unwrap())
        .collect::<Vec<PublicKey>>();

    let until = fetch_events(&client, follow_list.clone(), None).await;
    let mut until = until.add(Duration::from_millis(1));

    loop {
        let mut command = String::new();
        let _ = io::stdin().read_line(&mut command);

        if command.trim().is_empty() || command.trim_end_matches(&['\r', '\n'][..]).is_empty() {
            until = fetch_events(&client, follow_list.clone(), Some(until)).await;
        } else if command.trim().eq_ignore_ascii_case("q") {
            println!("bye!");
            break;
        } else {
            eprintln!("Error exit. Entered: {}", command.trim());
            break;
        }
    }
}

async fn fetch_events(client: &Client, authors: Vec<PublicKey>, until: Option<Timestamp>) -> Timestamp {
    let mut filter = Filter::new().kind(Kind::TextNote).authors(authors).limit(5);
    if let Some(ts) = until {
        filter = filter.clone().until(ts.add(Duration::from_nanos(1)));
    }
    let mut stream = client.stream_events(filter, Duration::from_secs(5)).await.unwrap();

    let mut last_event_ts = Timestamp::now();

    while let Some(event) = stream.next().await {
        last_event_ts = event.created_at;
        println!("{}", event.content);
        println!("by -> {}", event.pubkey);
        println!("link -> https://primal.net/e/{}", event.id);
        println!("-------------");
        println!();
    }
    last_event_ts
}

async fn connect_to_nostr(priv_key: Option<String>) -> Client {
    let mut client = Client::default();
    if let Some(priv_key) = priv_key {
        let keys = Keys::parse(priv_key.as_str());
        client = Client::new(keys.unwrap());
    }

    client.add_relay("wss://relay.damus.io").await.expect("Failed to add relay");
    client.add_relay("wss://atlas.nostr.land").await.expect("Failed to add relay");
    client.add_relay("wss://eden.nostr.land").await.expect("Failed to add relay");
    client.add_relay("wss://nos.lol").await.expect("Failed to add relay");
    client.add_relay("wss://nostr.land").await.expect("Failed to add relay");
    client.add_relay("wss://cache1.primal.net/v1").await.expect("Failed to add relay");

    client.connect().await;
    client
}

pub fn derive_pubkey(priv_key: &str) -> String {
    let keys = Keys::parse(priv_key);
    keys.expect("Failed to parse keys").public_key.to_string()
}