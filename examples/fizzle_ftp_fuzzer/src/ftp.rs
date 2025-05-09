use butterfly::{HasCrossoverInsertMutation, HasCrossoverReplaceMutation, HasHavocMutation, HasSpliceMutation};
use libafl::{inputs::BytesInput, mutators::{MutationId, MutationResult, MutatorsTuple}, state::{HasMaxSize, HasRand}};

use crate::proto::{PacketProtocol, ProtoParser};



#[derive(Clone, Debug, Hash, serde::Serialize, serde::Deserialize)]
pub enum FtpProtocol {
    USER(BytesInput),
    PASS(BytesInput),
    PASV,
    TYPE(u8, u8),
    LIST(Option<BytesInput>),
    CWD(BytesInput),
    QUIT,
}

impl FtpProtocol {
    fn inner_data(&self) -> Option<&BytesInput> {
        match self {
            Self::USER(data) |
            Self::PASS(data) |
            Self::CWD(data) |
            Self::LIST(Some(data)) => Some(data),
            _ => None,
        }
    }
    
    fn inner_data_mut(&mut self) -> Option<&mut BytesInput> {
        match self {
            Self::USER(data) |
            Self::PASS(data) |
            Self::CWD(data) |
            Self::LIST(Some(data)) => Some(data),
            _ => None,
        }
    }
}

impl PacketProtocol for FtpProtocol {
    type Parser = FtpParser;

    fn to_bytes_extend(&self, v: &mut Vec<u8>) {
        match self {
            FtpProtocol::USER(name) => {
                v.extend(b"USER ");
                v.extend(name.as_ref());
                v.extend(b"\r\n");
            },
            FtpProtocol::PASS(password) => {
                v.extend(b"PASS ");
                v.extend(password.as_ref());
                v.extend(b"\r\n");
            },
            FtpProtocol::PASV => {
                v.extend(b"PASV\r\n");
            },
            FtpProtocol::TYPE(arg1, arg2) => {
                v.extend(b"TYPE ");
                v.extend(&[*arg1, *arg2]);
                v.extend(b"\r\n");
            },
            FtpProtocol::LIST(dir) => {
                v.extend(b"LIST");

                if let Some(dir) = dir {
                    v.extend(b" ");
                    v.extend(dir.as_ref());
                }

                v.extend(b"\r\n");
            },
            FtpProtocol::CWD(dir) => {
                v.extend(b"CWD ");
                v.extend(dir.as_ref());
                v.extend(b"\r\n");
            },
            FtpProtocol::QUIT => {
                v.extend(b"QUIT\r\n");
            },
        }
    }

    fn from_pcap(mut capture: pcap::Capture<pcap::Offline>) -> Option<Vec<Self>> {
        // Packets extracted from pcap
        let mut packets = Vec::<FtpProtocol>::new();
        // Port numbers of the command connection: (client port, server port)
        let mut command_connection = None;
        
        while let Ok(packet) = capture.next_packet() {
            let packet = etherparse::PacketHeaders::from_ethernet_slice(&packet.data).unwrap();
            
            if let Some(etherparse::TransportHeader::Tcp(tcp)) = &packet.transport {
                let packet_ports = (tcp.source_port, tcp.destination_port);
                
                // Does the client make a connection to the server ?
                if tcp.syn && !tcp.ack {
                    // We only care about the first connection that is established as
                    // it is the command connection.
                    // All other connections are data connections which we don't care about.
                    if command_connection.is_none() {
                        command_connection = Some(packet_ports);
                    }
                }
                // Was the command connection closed ?
                else if tcp.fin || tcp.rst {
                    if Some(packet_ports) == command_connection {
                        break;
                    }
                }
                // Was data transferred ?
                else if packet.payload.len() > 4 {
                    if Some(packet_ports) == command_connection {
                        // First find the \r\n that terminates a command
                        let mut linebreak = 0;
                        while linebreak < packet.payload.len() - 1 {
                            if packet.payload[linebreak] == b'\r' && packet.payload[linebreak + 1] == b'\n' {
                                break;
                            }
                            linebreak += 1;
                        }
                        assert!(linebreak < packet.payload.len() - 1);
                        
                        // Then parse the command
                        let command = match &packet.payload[0..4] {
                            b"USER" => FtpProtocol::USER(BytesInput::new(packet.payload[5..linebreak].to_vec())),
                            b"PASS" => FtpProtocol::PASS(BytesInput::new(packet.payload[5..linebreak].to_vec())),
                            b"CWD " => FtpProtocol::CWD(BytesInput::new(packet.payload[4..linebreak].to_vec())),
                            b"PASV" => FtpProtocol::PASV,
                            b"TYPE" => {
                                if linebreak > 7 {
                                    FtpProtocol::TYPE(packet.payload[5], packet.payload[7])
                                } else {
                                    FtpProtocol::TYPE(packet.payload[5], b'N')
                                }
                            },
                            b"LIST" => {
                                if linebreak > 5 {
                                    FtpProtocol::LIST(Some(BytesInput::new(packet.payload[5..linebreak].to_vec())))
                                } else {
                                    FtpProtocol::LIST(None)
                                }
                            },
                            b"QUIT" => FtpProtocol::QUIT,
                            // Ignore other commands:
                            _ => continue,
                        };
                        
                        packets.push(command);
                    }
                }
            }
        }

        Some(packets)
    }
}

impl<S> HasCrossoverInsertMutation<S> for FtpProtocol
where 
    S: HasMaxSize + HasRand
{
    fn mutate_crossover_insert(&mut self, state: &mut S, other: &Self) -> Result<libafl::mutators::MutationResult, libafl::Error> {
        if let Some(data) = self.inner_data_mut() {
            if let Some(other_data) = other.inner_data() {
                return data.mutate_crossover_insert(state, other_data);
            }
        }
        
        Ok(MutationResult::Skipped)
    }
}

impl<S> HasCrossoverReplaceMutation<S> for FtpProtocol
where
    S: HasRand + HasMaxSize,
{
    fn mutate_crossover_replace(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, libafl::Error> {
        if let Some(data) = self.inner_data_mut() {
            if let Some(other_data) = other.inner_data() {
                return data.mutate_crossover_replace(state, other_data);
            }
        }
        
        Ok(MutationResult::Skipped)
    }
}

impl<S> HasSpliceMutation<S> for FtpProtocol
where
    S: HasRand + HasMaxSize,
{
    fn mutate_splice(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, libafl::Error> {
        if let Some(data) = self.inner_data_mut() {
            if let Some(other_data) = other.inner_data() {
                return data.mutate_splice(state, other_data);
            }
        }
        
        Ok(MutationResult::Skipped)
    }
}

impl<MT, S> HasHavocMutation<MT, S> for FtpProtocol 
where
   MT: MutatorsTuple<BytesInput, S>,
   S: HasRand + HasMaxSize,
{
    fn mutate_havoc(&mut self, state: &mut S, mutations: &mut MT, mutation: MutationId) -> Result<MutationResult, libafl::Error> {
        if let Some(data) = self.inner_data_mut() {
            data.mutate_havoc(state, mutations, mutation)
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

pub struct FtpParser {

}

impl ProtoParser for FtpParser {
    fn new() -> Self {
        Self {

        }
    }
}
