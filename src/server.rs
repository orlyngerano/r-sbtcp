use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::packet::{
    deserialize, DebugPacket, EndOfSessionPacket, LoginAcceptedPacket, LoginRejectedPacket,
    LoginRequestPacket, Packet, RejectReason, SequencedDataPacket, ServerHeartbeatPacket,
    UnsequencedDataPacket,
};

pub struct SessionState<'a> {
    pub session: [u8; 10],
    pub sequence_number: [u8; 20],
    pub socket: &'a TcpStream,
}

pub trait ServerEvent: Send + Copy + 'static {
    fn on_received(&self, packet: &Vec<u8>, socket: &TcpStream);
    fn on_closed(&self);
    fn on_opened(&self);
    fn on_login(&self, login_request_packet: LoginRequestPacket);
    fn on_logout(&self);
}

pub struct Server {
    ip_address: String,
    port_number: u16,
    socket: Option<TcpListener>,
}

impl Server {
    pub fn new(ip_address: String, port_number: u16) -> Self {
        Self {
            ip_address,
            port_number,
            socket: None,
        }
    }

    pub async fn listen(mut self, events: impl ServerEvent) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind((self.ip_address.clone(), self.port_number)).await?;
        self.socket = Some(listener);
        self.process(events).await?;
        Ok(())
    }

    async fn process(&mut self, events: impl ServerEvent) -> Result<(), Box<dyn Error>> {
        let socket = self.socket.as_mut().unwrap();
        loop {
            let (tcp_stream, _) = socket.accept().await?;

            let stream = Arc::new(Mutex::new(tcp_stream));

            let mut no_activity_expiration_secs = 0;

            // check for for heart beat
            let heartbeat_stream: Arc<Mutex<TcpStream>> = stream.clone();
            tokio::spawn(async move {
                loop {
                    sleep(Duration::from_millis(1000)).await;
                    no_activity_expiration_secs += 1;
                    let mut s = heartbeat_stream.lock().await;
                    if no_activity_expiration_secs > 15 {
                        let _ = Server::close(&mut s).await;
                        let _ = s.shutdown().await;
                        events.on_closed();
                        break;
                    } else {
                        let _ = Server::heartbeat_packet(&mut s).await;
                    }
                }
            });

            let common_stream = stream.clone();
            tokio::spawn(async move {
                events.on_opened();
                loop {
                    if no_activity_expiration_secs > 15 {
                        break;
                    }
                    let mut buffer: [u8; 1024] = [0; 1024];
                    let mut s = common_stream.lock().await;

                    let read_result = s.read(&mut buffer).await;
                    let read_size = read_result.unwrap();

                    if read_size > 0 {
                        // reset
                        no_activity_expiration_secs = 0;

                        // println!("Reading {}", read_size);
                        // println!("{:?}", &buffer[..read_size]);
                        let result = deserialize(buffer.to_vec());
                        let packet = result.unwrap();

                        match packet {
                            Packet::Debug(debug_packet) => {
                                println!("debug packet : {}", debug_packet.get_text());
                            }
                            Packet::SequencedData(sequenced_data_packet) => {
                                events.on_received(&sequenced_data_packet.message, &s);
                            }
                            Packet::UnsequencedData(unsequenced_data_packet) => {
                                events.on_received(&unsequenced_data_packet.message, &s);
                            }
                            Packet::LoginRequest(login_request_packet) => {
                                events.on_login(login_request_packet);
                            }
                            Packet::LogoutRequest(_) => {
                                events.on_logout();
                            }
                            Packet::ClientHeartbeat(_) => {
                                todo!()
                            }
                            _ => (),
                        }
                    }
                }
            });
        }
    }

    pub async fn accept_login(
        session: [u8; 10],
        sequence_number: [u8; 20],
        socket: &mut TcpStream,
    ) -> Result<(), Box<dyn Error>> {
        let mut packet = LoginAcceptedPacket::new();
        packet.session = session;
        packet.sequence_number = sequence_number;
        socket.write(&packet.to_bytes()).await?;
        Ok(())
    }

    pub async fn reject_login(
        reason: RejectReason,
        socket: &mut TcpStream,
    ) -> Result<(), Box<dyn Error>> {
        let mut packet = LoginRejectedPacket::new();
        packet.reject_reason = reason;
        socket.write(&packet.to_bytes()).await?;
        Ok(())
    }

    pub async fn close(socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        let mut packet = EndOfSessionPacket::new();
        socket.write(&packet.to_bytes()).await?;
        Ok(())
    }

    pub async fn send_sequence_message(
        message: Vec<u8>,
        socket: &mut TcpStream,
    ) -> Result<(), Box<dyn Error>> {
        let mut packet = SequencedDataPacket::new();
        packet.message = message;
        socket.write(&packet.to_bytes()).await?;
        Ok(())
    }

    pub async fn send_unsequence_message(
        message: Vec<u8>,
        socket: &mut TcpStream,
    ) -> Result<(), Box<dyn Error>> {
        let mut packet = UnsequencedDataPacket::new();
        packet.message = message;
        socket.write(&packet.to_bytes()).await?;
        Ok(())
    }

    pub async fn debug_packet(socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        let mut packet = DebugPacket::new();
        socket.write(&packet.to_bytes()).await?;
        Ok(())
    }

    pub async fn heartbeat_packet(socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        let mut packet = ServerHeartbeatPacket::new();
        socket.write(&packet.to_bytes()).await?;
        Ok(())
    }
}
