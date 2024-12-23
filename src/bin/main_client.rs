// Example how upper protocol such as OUCH and ICH can use soupbintcp
use std::error::Error;

use r_sbtcp::client::{Client, ClientEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::new(String::from("localhost"), 8100);
    let client_event = ClientEventHandler {};
    client.connect(&client_event).await?;
    Ok(())
}

struct ClientEventHandler;

impl ClientEvent for ClientEventHandler {
    fn on_received(&self, packet: &Vec<u8>) {
        todo!()
    }

    fn on_closed(&self) {
        todo!()
    }

    fn on_opened(&self) {
        todo!()
    }

    fn on_login_accepted(&self, login_accepted_packet: r_sbtcp::packet::LoginAcceptedPacket) {
        todo!()
    }

    fn on_logout(&self) {
        todo!()
    }

    fn on_login_rejected(&self, login_rejected_packet: r_sbtcp::packet::LoginRejectedPacket) {
        todo!()
    }
}
