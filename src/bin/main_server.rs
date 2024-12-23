// Example how upper protocol such as OUCH and ICH can use soupbintcp

use std::error::Error;

use r_sbtcp::server::{Server, ServerEvent};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server = Server::new(String::from("localhost"), 8100);
    let server_event = ServerEventHandler {};
    server.listen(server_event).await?;
    Ok(())
}

#[derive(Copy, Clone)]
struct ServerEventHandler;

impl ServerEvent for ServerEventHandler {
    fn on_received(&self, packet: &Vec<u8>, tcp_stream: &TcpStream) {
        todo!()
    }

    fn on_closed(&self) {
        todo!()
    }

    fn on_opened(&self) {
        todo!()
    }

    fn on_logout(&self) {
        todo!()
    }

    fn on_login(&self, login_request_packet: r_sbtcp::packet::LoginRequestPacket) {
        todo!()
    }
}
