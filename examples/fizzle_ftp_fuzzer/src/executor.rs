use std::fmt::{Debug, Formatter};

use butterfly::StateObserver;
use libafl::{executors::{Executor, ExitKind, ForkserverExecutor, HasObservers}, inputs::TargetBytesConverter, observers::ObserversTuple, state::HasExecutions};
use libafl_bolts::{shmem::ShMem, Error};
use libafl_bolts::tuples::{MatchName, RefIndexable};

use crate::{observer::{PacketResponseMapObserver, PKT_RSP_MAP_NAME}, proto::{PacketProtocol, Packets, ProtoParser}};

pub struct FizzleExecutor<OT, PKT, S, SHM, TC>
where
    OT: ObserversTuple<Packets<PKT>, S> + MatchName,
    PKT: PacketProtocol,
{
    proto_parser: PKT::Parser,
    inner_executor: ForkserverExecutor<Packets<PKT>, OT, S, SHM, TC>,
}

impl<OT, PKT, S, SHM, TC> FizzleExecutor<OT, PKT, S, SHM, TC>
where
    OT: ObserversTuple<Packets<PKT>, S>,
    PKT: PacketProtocol,
{
    pub fn new(forksrv_executor: ForkserverExecutor<Packets<PKT>, OT, S, SHM, TC>) -> Self {
        Self {
            proto_parser: PKT::Parser::new(),
            inner_executor: forksrv_executor,
        }
    }
}

impl<OT, PKT, S, SHM, TC> Debug for FizzleExecutor<OT, PKT, S, SHM, TC>
where
    OT: ObserversTuple<Packets<PKT>, S>,
    PKT: PacketProtocol,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "FizzleExecutor {{ <opaque> }}")
    }
}

impl<OT, PKT, S, SHM, TC> HasObservers for FizzleExecutor<OT, PKT, S, SHM, TC>
where
    OT: ObserversTuple<Packets<PKT>, S>,
    PKT: PacketProtocol,
{
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&OT, OT> {
        self.inner_executor.observers()
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut OT, OT> {
        self.inner_executor.observers_mut()
    }
}

impl<EM, OT, PKT, S, SHM, TC, Z> Executor<EM, Packets<PKT>, S, Z> for FizzleExecutor<OT, PKT, S, SHM, TC>
where
    OT: ObserversTuple<Packets<PKT>, S>,
    S: HasExecutions,
    PKT: PacketProtocol,
    SHM: ShMem,
    TC: TargetBytesConverter<Packets<PKT>>,
{
    #[allow(unused_variables,unused_assignments)]
    fn run_target(&mut self, fuzzer: &mut Z, state: &mut S, mgr: &mut EM, input: &Packets<PKT>) -> Result<ExitKind, Error> {

        // Tell butterfly the state that we entered
        // state_observer.record(&status_code);


        let ret = self.inner_executor.run_target(fuzzer, state, mgr, input);

        // TODO: implement response inferrence later
        /*
        // TODO: record responses as clusters from individual requests (for protocols that employ multiple responses)
        let observers = self.observers();
        let response_observer: &PacketResponseMapObserver<'_> = observers.match_name(PKT_RSP_MAP_NAME).unwrap();
        let responses = response_observer.responses();
        drop(observers);
        for response in responses {
            if let Some(rsp) = PKT::parse_response(&mut self.proto_parser, response) {
                let mut observers = self.observers_mut();
                let state_observer: &mut StateObserver<u32> = observers.match_name_mut("ButterflyState").unwrap();
                state_observer.record(&rsp);
            }
        }

        for packet in input.packets() {
            PKT::parse_request(&mut self.proto_parser, packet);



            // state_observer.record();
        }
        */

        ret

        /*
        match self.get_response(&mut cmd_conn) {
            Some(220) => {},
            _ => {
                return Ok(ExitKind::Ok);
            },
        }
        
        for packet in input.packets() {
            // Send command
            let read_resp = match packet {
                FTPCommand::USER(name) => {
                    cmd_conn.write_all(b"USER ")?;
                    cmd_conn.write_all(name.as_ref())?;
                    cmd_conn.write_all(b"\r\n")?;
                    cmd_conn.flush()?;
                    true
                },
                FTPCommand::PASS(password) => {
                    cmd_conn.write_all(b"PASS ")?;
                    cmd_conn.write_all(password.as_ref())?;
                    cmd_conn.write_all(b"\r\n")?;
                    cmd_conn.flush()?;
                    true
                },
                FTPCommand::PASV => {
                    cmd_conn.write_all(b"PASV\r\n")?;
                    
                    match self.get_response(&mut cmd_conn) {
                        Some(227) => {
                            if let Some(address) = self.parse_pasv_response() {
                                data_conn = Some(TcpStream::connect(address).expect("data connection"));
                            } else {
                                panic!("Could not parse PASV response: {:?}", self.buf);
                            }
                        },
                        Some(code) => {},
                        None => {
                            return Ok(ExitKind::Crash);
                        },
                    }
                    
                    false
                },
                FTPCommand::TYPE(arg1, arg2) => {
                    cmd_conn.write_all(b"TYPE ")?;
                    cmd_conn.write_all(&[*arg1, *arg2])?;
                    cmd_conn.write_all(b"\r\n")?;
                    cmd_conn.flush()?;
                    true
                },
                FTPCommand::LIST(dir) => {
                    cmd_conn.write_all(b"LIST")?;
                    
                    if let Some(dir) = dir {
                        cmd_conn.write_all(b" ")?;
                        cmd_conn.write_all(dir.as_ref())?;
                    }
                    
                    cmd_conn.write_all(b"\r\n")?;
                    cmd_conn.flush()?;
                    
                    match self.get_response(&mut cmd_conn) {
                        Some(150) => {
                            // Ignore the listing sent over the data connection
                            // and wait until server notifies us that the transfer
                            // is complete
                            
                            match self.get_response(&mut cmd_conn) {
                                Some(_) => {},
                                None => {
                                    return Ok(ExitKind::Crash);
                                },
                            }
                            
                            // Close the data connection
                            data_conn = None;
                        },
                        Some(_) => {},
                        None => {
                            return Ok(ExitKind::Crash);
                        },
                    }
                    
                    false
                },
                FTPCommand::CWD(dir) => {
                    cmd_conn.write_all(b"CWD ")?;
                    cmd_conn.write_all(dir.as_ref())?;
                    cmd_conn.write_all(b"\r\n")?;
                    cmd_conn.flush()?;
                    true
                },
                FTPCommand::QUIT => {
                    cmd_conn.write_all(b"QUIT\r\n")?;
                    cmd_conn.flush()?;
                    
                    if self.get_response(&mut cmd_conn).is_none() {
                        return Ok(ExitKind::Crash);
                    }
                    
                    break;
                },
            };
            
            // Receive reply. If the target crashed on one of our commands
            // it does not send a reply.
            if read_resp && self.get_response(&mut cmd_conn).is_none() {
                return Ok(ExitKind::Crash);
            }
        }
        
        Ok(ExitKind::Ok)
        */
    }
}