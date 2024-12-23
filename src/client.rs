use std::error::Error;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::packet::{deserialize, LoginAcceptedPacket, LoginRejectedPacket, Packet};

pub trait ClientEvent {
    fn on_received(&self, packet: &Vec<u8>);
    fn on_closed(&self);
    fn on_opened(&self);
    fn on_login_accepted(&self, login_accepted_packet: LoginAcceptedPacket);
    fn on_login_rejected(&self, login_rejected_packet: LoginRejectedPacket);
    fn on_logout(&self);
}

pub struct Client {
    ip_address: String,
    port_number: u16,
    socket: Option<TcpStream>,
}

impl Client {
    pub fn new(ip_address: String, port_number: u16) -> Self {
        Self {
            ip_address,
            port_number,
            socket: None,
        }
    }

    pub async fn connect(mut self, events: &impl ClientEvent) -> Result<(), Box<dyn Error>> {
        let socket = TcpStream::connect((self.ip_address.clone(), self.port_number)).await?;
        self.socket = Some(socket);
        self.process(events).await?;
        Ok(())
    }

    async fn process(&mut self, events: &impl ClientEvent) -> Result<(), Box<dyn Error>> {
        let socket = self.socket.as_mut().unwrap();

        loop {
            let mut buffer: [u8; 1024] = [0; 1024];
            let read_size = socket.read(&mut buffer).await?;

            if read_size > 0 {
                // println!("Reading {}", read_size);
                // println!("{:?}", &buffer[..read_size]);
                let result = deserialize(buffer.to_vec());
                let packet = result.unwrap();

                match packet {
                    Packet::Debug(debug_packet) => {
                        println!("debug packet : {}", debug_packet.get_text());
                    }
                    Packet::LoginAccepted(login_accepted_packet) => {
                        events.on_login_accepted(login_accepted_packet);
                    }
                    Packet::LoginRejected(login_rejected_packet) => {
                        events.on_login_rejected(login_rejected_packet);
                    }
                    Packet::SequencedData(sequenced_data_packet) => {
                        events.on_received(&sequenced_data_packet.message);
                    }
                    Packet::UnsequencedData(unsequenced_data_packet) => {
                        events.on_received(&unsequenced_data_packet.message);
                    }
                    Packet::ServerHeartbeat(server_heartbeat_packet) => {
                        todo!()
                    }
                    _ => (),
                }
            }
        }
    }
}
