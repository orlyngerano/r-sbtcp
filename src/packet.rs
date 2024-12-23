use std::vec;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum PacketType {
    Debug = 0x2b,           // + char
    LoginAccepted = 0x41,   // A
    LoginRejected = 0x4a,   // J
    SequencedData = 0x53,   // S
    UnsequencedData = 0x55, // U
    ServerHeartbeat = 0x48, // H
    EndOfSession = 0x5A,    // Z
    LoginRequest = 0x4C,    // L
    ClientHeartbeat = 0x52, // R
    LogoutRequest = 0x4F,   // O
    Invalid = 0x0,
}

impl From<u8> for PacketType {
    fn from(item: u8) -> Self {
        match item {
            0x2b => PacketType::Debug,
            0x41 => PacketType::LoginAccepted,
            0x4a => PacketType::LoginRejected,
            0x53 => PacketType::SequencedData,
            0x55 => PacketType::UnsequencedData,
            0x48 => PacketType::ServerHeartbeat,
            0x5A => PacketType::EndOfSession,
            0x4C => PacketType::LoginRequest,
            0x52 => PacketType::ClientHeartbeat,
            0x4F => PacketType::LogoutRequest,
            _ => PacketType::Invalid,
        }
    }
}

impl Into<u8> for PacketType {
    fn into(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum RejectReason {
    NotAvailable = 0x00,
    NotAuthorized = 0x41,       // A
    SessionNotAvailable = 0x53, // S
}

impl From<u8> for RejectReason {
    fn from(item: u8) -> Self {
        match item {
            0x41 => RejectReason::NotAuthorized,
            0x53 => RejectReason::SessionNotAvailable,
            _ => RejectReason::NotAvailable,
        }
    }
}

pub struct HeaderPacket {
    pub length: u16,
    pub packet_type: PacketType,
}

impl HeaderPacket {
    fn to_bytes(&mut self) -> Vec<u8> {
        let mut buffer = vec![];
        WriteBytesExt::write_u16::<BigEndian>(&mut buffer, self.length).unwrap();
        buffer.push(self.packet_type.into());
        buffer
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let mut header_length = &packet[0..=1];
        let length = ReadBytesExt::read_u16::<BigEndian>(&mut header_length).unwrap();

        let packet_type = PacketType::from(packet[2]);

        HeaderPacket {
            length,
            packet_type,
        }
    }
}
pub struct DebugPacket {
    pub header: HeaderPacket,
    pub text: String,
}

impl DebugPacket {
    pub fn new() -> Self {
        Self {
            header: HeaderPacket {
                length: 1,
                packet_type: PacketType::Debug,
            },
            text: String::new(),
        }
    }

    pub fn from(text: String) -> Self {
        let mut debug_packet = Self::new();
        debug_packet.set_text(text);
        debug_packet
    }

    pub fn set_text(&mut self, text: String) {
        self.text = text;
        self.header.length = 1 + self.text.len() as u16;
    }

    pub fn get_text(&self) -> &String {
        &self.text
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut buffer = self.header.to_bytes();
        let mut byte_string = self.text.clone().into_bytes();
        buffer.append(&mut byte_string);
        buffer
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let header = HeaderPacket::from_bytes(&packet);
        let payload = &packet[3..];
        let text = std::str::from_utf8(payload).unwrap().to_string();
        DebugPacket { header, text }
    }
}

pub struct LoginAcceptedPacket {
    pub header: HeaderPacket,
    pub session: [u8; 10],
    pub sequence_number: [u8; 20],
}

impl LoginAcceptedPacket {
    pub fn new() -> Self {
        Self {
            header: HeaderPacket {
                length: 31,
                packet_type: PacketType::LoginAccepted,
            },
            session: [0; 10],
            sequence_number: [0; 20],
        }
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut buffer = self.header.to_bytes();
        buffer.extend_from_slice(&self.session);
        buffer.extend_from_slice(&self.sequence_number);
        buffer
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let header = HeaderPacket::from_bytes(&packet);

        let mut session: [u8; 10] = [0; 10];
        session.copy_from_slice(&packet[3..=12]);

        let mut sequence_number: [u8; 20] = [0; 20];
        sequence_number.copy_from_slice(&packet[13..=32]);

        LoginAcceptedPacket {
            header,
            session,
            sequence_number,
        }
    }
}

pub struct LoginRejectedPacket {
    pub header: HeaderPacket,
    pub reject_reason: RejectReason,
}

impl LoginRejectedPacket {
    pub fn new() -> Self {
        Self {
            header: HeaderPacket {
                length: 2,
                packet_type: PacketType::LoginRejected,
            },
            reject_reason: RejectReason::NotAvailable,
        }
    }
    pub fn set_reject_reason(mut self, reason: RejectReason) {
        self.reject_reason = reason;
    }

    pub fn get_reject_reason(self) -> RejectReason {
        self.reject_reason
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut buffer = self.header.to_bytes();
        buffer.push(self.reject_reason as u8);
        buffer
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let header = HeaderPacket::from_bytes(&packet);

        let reject_reason = RejectReason::from(packet[3]);

        LoginRejectedPacket {
            header,
            reject_reason,
        }
    }
}

pub struct SequencedDataPacket {
    pub header: HeaderPacket,
    pub message: Vec<u8>,
}

impl SequencedDataPacket {
    pub fn new() -> Self {
        Self {
            header: HeaderPacket {
                length: 1,
                packet_type: PacketType::SequencedData,
            },
            message: vec![],
        }
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut buffer = self.header.to_bytes();
        buffer.append(&mut self.message);
        buffer
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let header = HeaderPacket::from_bytes(&packet);
        let mut message: Vec<u8> = vec![];
        message.copy_from_slice(&packet[3..]);
        SequencedDataPacket { header, message }
    }
}

pub struct UnsequencedDataPacket {
    pub header: HeaderPacket,
    pub message: Vec<u8>,
}

impl UnsequencedDataPacket {
    pub fn new() -> Self {
        Self {
            header: HeaderPacket {
                length: 1,
                packet_type: PacketType::UnsequencedData,
            },
            message: vec![],
        }
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut buffer = self.header.to_bytes();
        buffer.append(&mut self.message);
        buffer
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let header = HeaderPacket::from_bytes(&packet);
        let mut message: Vec<u8> = vec![];
        message.copy_from_slice(&packet[3..]);
        UnsequencedDataPacket { header, message }
    }
}
pub struct ServerHeartbeatPacket {
    pub header: HeaderPacket,
}

impl ServerHeartbeatPacket {
    pub fn new() -> Self {
        Self {
            header: HeaderPacket {
                length: 1,
                packet_type: PacketType::ServerHeartbeat,
            },
        }
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let buffer = self.header.to_bytes();
        buffer
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let header = HeaderPacket::from_bytes(&packet);
        ServerHeartbeatPacket { header }
    }
}

pub struct EndOfSessionPacket {
    pub header: HeaderPacket,
}

impl EndOfSessionPacket {
    pub fn new() -> Self {
        Self {
            header: HeaderPacket {
                length: 1,
                packet_type: PacketType::EndOfSession,
            },
        }
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let buffer = self.header.to_bytes();
        buffer
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let header = HeaderPacket::from_bytes(&packet);
        EndOfSessionPacket { header }
    }
}

pub struct LoginRequestPacket {
    pub header: HeaderPacket,
    pub username: [u8; 6],
    pub password: [u8; 10],
    pub requested_session: [u8; 10],
    pub requested_sequence_number: [u8; 20],
}

impl LoginRequestPacket {
    pub fn new() -> Self {
        Self {
            header: HeaderPacket {
                length: 1,
                packet_type: PacketType::LoginRequest,
            },
            username: [0; 6],
            password: [0; 10],
            requested_session: [0; 10],
            requested_sequence_number: [0; 20],
        }
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut buffer = self.header.to_bytes();
        buffer.extend_from_slice(&self.username);
        buffer.extend_from_slice(&self.password);
        buffer.extend_from_slice(&self.requested_session);
        buffer.extend_from_slice(&self.requested_sequence_number);
        buffer
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let header = HeaderPacket::from_bytes(&packet);

        let mut username: [u8; 6] = [0; 6];
        username.copy_from_slice(&packet[3..=8]);

        let mut password: [u8; 10] = [0; 10];
        password.copy_from_slice(&packet[9..=18]);

        let mut requested_session: [u8; 10] = [0; 10];
        requested_session.copy_from_slice(&packet[19..=28]);

        let mut requested_sequence_number: [u8; 20] = [0; 20];
        requested_sequence_number.copy_from_slice(&packet[29..=48]);

        LoginRequestPacket {
            header,
            username,
            password,
            requested_session,
            requested_sequence_number,
        }
    }
}

pub struct ClientHeartbeatPacket {
    pub header: HeaderPacket,
}

impl ClientHeartbeatPacket {
    pub fn new() -> Self {
        Self {
            header: HeaderPacket {
                length: 1,
                packet_type: PacketType::ClientHeartbeat,
            },
        }
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let header = HeaderPacket::from_bytes(&packet);
        ClientHeartbeatPacket { header }
    }
}

pub struct LogoutRequestPacket {
    pub header: HeaderPacket,
}

impl LogoutRequestPacket {
    pub fn new() -> Self {
        Self {
            header: HeaderPacket {
                length: 1,
                packet_type: PacketType::LogoutRequest,
            },
        }
    }

    pub fn to_bytes(&mut self) -> Vec<u8> {
        let buffer = self.header.to_bytes();
        buffer
    }

    pub fn from_bytes(packet: &Vec<u8>) -> Self {
        let header = HeaderPacket::from_bytes(&packet);
        LogoutRequestPacket { header }
    }
}

pub enum Packet {
    Debug(DebugPacket),
    LoginAccepted(LoginAcceptedPacket),
    LoginRejected(LoginRejectedPacket),
    SequencedData(SequencedDataPacket),
    UnsequencedData(UnsequencedDataPacket),
    ServerHeartbeat(ServerHeartbeatPacket),
    EndOfSession(EndOfSessionPacket),
    LoginRequest(LoginRequestPacket),
    ClientHeartbeat(ClientHeartbeatPacket),
    LogoutRequest(LogoutRequestPacket),
}

pub fn deserialize(packet: Vec<u8>) -> Result<Packet, String> {
    //check packet at least 3 bytes
    if packet.len() < 3 {
        return Err(String::from("Invalid Packet"));
    }

    //check packet type
    let packet_type = PacketType::from(packet[2]);
    match packet_type {
        PacketType::Debug => Ok(Packet::Debug(DebugPacket::from_bytes(&packet))),
        PacketType::LoginAccepted => Ok(Packet::LoginAccepted(LoginAcceptedPacket::from_bytes(
            &packet,
        ))),
        PacketType::LoginRejected => Ok(Packet::LoginRejected(LoginRejectedPacket::from_bytes(
            &packet,
        ))),
        PacketType::SequencedData => Ok(Packet::SequencedData(SequencedDataPacket::from_bytes(
            &packet,
        ))),
        PacketType::UnsequencedData => Ok(Packet::UnsequencedData(
            UnsequencedDataPacket::from_bytes(&packet),
        )),
        PacketType::ServerHeartbeat => Ok(Packet::ServerHeartbeat(
            ServerHeartbeatPacket::from_bytes(&packet),
        )),
        PacketType::EndOfSession => Ok(Packet::EndOfSession(EndOfSessionPacket::from_bytes(
            &packet,
        ))),
        PacketType::LoginRequest => Ok(Packet::LoginRequest(LoginRequestPacket::from_bytes(
            &packet,
        ))),
        PacketType::ClientHeartbeat => Ok(Packet::ClientHeartbeat(
            ClientHeartbeatPacket::from_bytes(&packet),
        )),
        PacketType::LogoutRequest => Ok(Packet::LogoutRequest(LogoutRequestPacket::from_bytes(
            &packet,
        ))),
        PacketType::Invalid => Err(String::from("Invalid Packet")),
    }
}
