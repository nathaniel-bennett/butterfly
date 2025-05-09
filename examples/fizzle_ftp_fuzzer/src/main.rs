mod executor;
mod observer;
mod proto;
mod ftp;

use executor::FizzleExecutor;
use libafl_bolts::{
        rands::StdRand, shmem::{ShMem, ShMemProvider, UnixShMemProvider}, tuples::{tuple_list, MatchName, RefIndexable}, AsSliceMut, HasLen
    };
use libafl::{
    corpus::{CorpusId, InMemoryCorpus}, events::SimpleEventManager, executors::{Executor, ExitKind, ForkserverExecutor, HasObservers}, feedback_or, feedback_or_fast, feedbacks::{CrashFeedback, MapFeedback, TimeoutFeedback}, inputs::{BytesInput, Input}, monitors::TuiMonitor, mutators::{MutationId, MutationResult, MutatorsTuple}, observers::{HitcountsMapObserver, ObserversTuple, StdMapObserver}, schedulers::QueueScheduler, stages::StdMutationalStage, state::{HasMaxSize, HasRand, StdState}, Error, Fuzzer, StdFuzzer
};
use butterfly::{
    HasPackets, StateObserver, StateMonitor, 
    StateFeedback, PacketMutationScheduler,
    PacketReorderMutator, PacketDeleteMutator, PacketDuplicateMutator,
    PacketCrossoverInsertMutator, HasCrossoverInsertMutation,
    HasCrossoverReplaceMutation, PacketCrossoverReplaceMutator,
    HasSpliceMutation, PacketSpliceMutator,
    HasHavocMutation, PacketHavocMutator, supported_havoc_mutations,
    HasPcapRepresentation, load_pcaps, GraphvizMonitor,
};
use observer::PacketResponseMapObserver;
use proto::{OpaqueParser, OpaqueProtocol, Packets};
use serde::{Serialize, Deserialize};
use std::{env, marker::PhantomData, time::Duration};
use std::fmt::{Debug, Formatter};
use std::net::{TcpStream, SocketAddrV4, Ipv4Addr};
use std::io::{Read, Write};
use pcap::{Capture, Offline};
use etherparse;

/*

fn parse_decimal(buf: &[u8]) -> (u32, usize) {
    let mut res = 0;
    let mut len = 0;
    
    for c in buf {
        if *c >= 0x30 && *c <= 0x39 {
            res *= 10;
            res += *c as u32 - 0x30;
        } else {
            break;
        }
        
        len += 1;
    }
    
    (res, len)
}

#[derive(Hash, Debug, Clone, Serialize, Deserialize)]
enum FTPCommand {
    USER(BytesInput),
    PASS(BytesInput),
    PASV,
    TYPE(u8, u8),
    LIST(Option<BytesInput>),
    CWD(BytesInput),
    QUIT,
}

impl FTPCommand {
    fn inner_data(&self) -> Option<&BytesInput> {
        match self {
            FTPCommand::USER(data) |
            FTPCommand::PASS(data) |
            FTPCommand::CWD(data) |
            FTPCommand::LIST(Some(data)) => Some(data),
            _ => None,
        }
    }
    
    fn inner_data_mut(&mut self) -> Option<&mut BytesInput> {
        match self {
            FTPCommand::USER(data) |
            FTPCommand::PASS(data) |
            FTPCommand::CWD(data) |
            FTPCommand::LIST(Some(data)) => Some(data),
            _ => None,
        }
    }
}

impl<S> HasCrossoverInsertMutation<S> for FTPCommand
where
    S: HasRand + HasMaxSize,
{
    fn mutate_crossover_insert(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error> {
        if let Some(data) = self.inner_data_mut() {
            if let Some(other_data) = other.inner_data() {
                return data.mutate_crossover_insert(state, other_data);
            }
        }
        
        Ok(MutationResult::Skipped)
    }
}

impl<S> HasCrossoverReplaceMutation<S> for FTPCommand
where
    S: HasRand + HasMaxSize,
{
    fn mutate_crossover_replace(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error> {
        if let Some(data) = self.inner_data_mut() {
            if let Some(other_data) = other.inner_data() {
                return data.mutate_crossover_replace(state, other_data);
            }
        }
        
        Ok(MutationResult::Skipped)
    }
}

impl<S> HasSpliceMutation<S> for FTPCommand
where
    S: HasRand + HasMaxSize,
{
    fn mutate_splice(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error> {
        if let Some(data) = self.inner_data_mut() {
            if let Some(other_data) = other.inner_data() {
                return data.mutate_splice(state, other_data);
            }
        }
        
        Ok(MutationResult::Skipped)
    }
}

impl<MT, S> HasHavocMutation<MT, S> for FTPCommand
where
   MT: MutatorsTuple<BytesInput, S>,
   S: HasRand + HasMaxSize,
{
    fn mutate_havoc(&mut self, state: &mut S, mutations: &mut MT, mutation: MutationId) -> Result<MutationResult, Error> {
        if let Some(data) = self.inner_data_mut() {
            data.mutate_havoc(state, mutations, mutation)
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}


#[derive(Hash, Debug, Clone, Serialize, Deserialize)]
struct FTPInput {
    packets: Vec<FTPCommand>
}

impl HasPackets<FTPCommand> for FTPInput {
    fn packets(&self) -> &[FTPCommand] {
        &self.packets
    }
    
    fn packets_mut(&mut self) -> &mut Vec<FTPCommand> {
        &mut self.packets
    }
}

impl HasLen for FTPInput {
    fn len(&self) -> usize {
        self.packets.len()
    }
}

impl Input for FTPInput {
    fn generate_name(&self, idx: Option<CorpusId>) -> String {
        // generally a bad idea but for this example ok
        format!("ftpinput-{:?}", idx)
    }
}

// Add pcap support to FTPInput
impl HasPcapRepresentation<FTPInput> for FTPInput {
    fn from_pcap(mut capture: Capture<Offline>) -> Result<FTPInput, Error> {
        // Packets extracted from pcap
        let mut packets = Vec::<FTPCommand>::new();
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
                            b"USER" => FTPCommand::USER(BytesInput::new(packet.payload[5..linebreak].to_vec())),
                            b"PASS" => FTPCommand::PASS(BytesInput::new(packet.payload[5..linebreak].to_vec())),
                            b"CWD " => FTPCommand::CWD(BytesInput::new(packet.payload[4..linebreak].to_vec())),
                            b"PASV" => FTPCommand::PASV,
                            b"TYPE" => {
                                if linebreak > 7 {
                                    FTPCommand::TYPE(packet.payload[5], packet.payload[7])
                                } else {
                                    FTPCommand::TYPE(packet.payload[5], b'N')
                                }
                            },
                            b"LIST" => {
                                if linebreak > 5 {
                                    FTPCommand::LIST(Some(BytesInput::new(packet.payload[5..linebreak].to_vec())))
                                } else {
                                    FTPCommand::LIST(None)
                                }
                            },
                            b"QUIT" => FTPCommand::QUIT,
                            // Ignore other commands:
                            _ => continue,
                        };
                        
                        packets.push(command);
                    }
                }
            }
        }
        
        Ok(FTPInput {
            packets
        })
    }
}


struct FTPExecutor<OT, S>
where
    OT: ObserversTuple<FTPInput, S> + MatchName,
{
    observers: OT,
    buf: Vec<u8>,
    phantom: PhantomData<S>,
}

impl<OT, S> FTPExecutor<OT, S>
where
    OT: ObserversTuple<FTPInput, S>,
{
    fn new(observers: OT) -> Self {
        Self {
            observers,
            buf: vec![0; 4096],
            phantom: PhantomData,
        }
    }
    
    fn get_response(&mut self, cmd_conn: &mut TcpStream) -> Option<u32> {
        let num_read = match cmd_conn.read(&mut self.buf) {
            Ok(num_read) => num_read,
            
            // If we hit an error then we assume the target crashed
            Err(_) => {
                return None;
            }
        };
        
        // Malformed response
        if num_read < 5 {
            return Some(0);
        }
        
        // Parse the status code
        let (status_code, len) = parse_decimal(&self.buf[0..num_read]);
        
        if len != 3 {
            return Some(0);
        }
        
        // Tell butterfly the state that we entered
        let state_observer: &mut StateObserver<u32> = self.observers.match_name_mut("ButterflyState").unwrap();
        state_observer.record(&status_code);
        
        // Return the status code
        Some(status_code)
    }
    
    fn parse_pasv_response(&self) -> Option<SocketAddrV4> {
        let mut i = 0;
        
        // Skip to first '('
        while i < self.buf.len() {
            if self.buf[i] == b'(' {
                i += 1;
                break;
            }
            
            i += 1;
        }
        
        // Get a1
        let (a1, len) = parse_decimal(&self.buf[i..]);
        
        if len < 1 {
            return None;
        }
        
        i += len;
        
        if i < self.buf.len() && self.buf[i] != b',' {
            return None;
        } else {
            i += 1;
        }
        
        // Get a2
        let (a2, len) = parse_decimal(&self.buf[i..]);
        
        if len < 1 {
            return None;
        }
        
        i += len;
        
        if i < self.buf.len() && self.buf[i] != b',' {
            return None;
        } else {
            i += 1;
        }
        
        // Get a3
        let (a3, len) = parse_decimal(&self.buf[i..]);
        
        if len < 1 {
            return None;
        }
        
        i += len;
        
        if i < self.buf.len() && self.buf[i] != b',' {
            return None;
        } else {
            i += 1;
        }
        
        // Get a4
        let (a4, len) = parse_decimal(&self.buf[i..]);
        
        if len < 1 {
            return None;
        }
        
        i += len;
        
        if i < self.buf.len() && self.buf[i] != b',' {
            return None;
        } else {
            i += 1;
        }
        
        // Get p1
        let (p1, len) = parse_decimal(&self.buf[i..]);
        
        if len < 1 {
            return None;
        }
        
        i += len;
        
        if i < self.buf.len() && self.buf[i] != b',' {
            return None;
        } else {
            i += 1;
        }
        
        // Get p2
        let (p2, len) = parse_decimal(&self.buf[i..]);
        
        if len < 1 {
            return None;
        }
        
        i += len;
        
        if i < self.buf.len() && self.buf[i] != b')' {
            return None;
        }
        
        Some(SocketAddrV4::new(
            Ipv4Addr::new(a1 as u8, a2 as u8, a3 as u8, a4 as u8),
            (p1 * 256 + p2) as u16,
        ))
    }
}

impl<OT, S> Debug for FTPExecutor<OT, S>
where
    OT: ObserversTuple<FTPInput, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "FTPExecutor {{ }}")
    }
}

impl<OT, S> HasObservers for FTPExecutor<OT, S>
where
    OT: ObserversTuple<FTPInput, S>,
{
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&OT, OT> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut OT, OT> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<OT, S, EM, Z> Executor<EM, FTPInput, S, Z> for FTPExecutor<OT, S>
where
    OT: ObserversTuple<FTPInput, S>,
{
    #[allow(unused_variables,unused_assignments)]
    fn run_target(&mut self, _fuzzer: &mut Z, _state: &mut S, _mgr: &mut EM, input: &FTPInput) -> Result<ExitKind, Error> {
        let mut cmd_conn: TcpStream;
        let mut data_conn: Option<TcpStream> = None;
        
        // Apparently, if we establish too many connections in a short amount of time
        // LightFTP stops working.
        std::thread::sleep(std::time::Duration::from_millis(50));
        
        // connect to the server
        cmd_conn = TcpStream::connect("127.0.0.1:2121").expect("command connection");
        
        // initial 220 reply.
        // if we don't get a 220 we will most likely get
        // the message "MAXIMUM ALLOWED USERS CONNECTED"
        // so we just cancel the execution.
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
    }
}
*/

fn main() {
    const MAP_SIZE: usize = 65536;
    // const FIZZLE_RSPBUF_SIZE: usize = 65536 * 16; // The map that returns response values

    let tui_monitor = TuiMonitor::builder()
        .enhanced_graphics(true)
        .title("Fizzle ⚡🔌⚡")
        .version("0.1.0")
        .build();

    /*
    let mut fizzle_shmem_provider = UnixShMemProvider::new().unwrap();
    let mut fizzle_shmem = fizzle_shmem_provider.new_shmem(FIZZLE_RSPBUF_SIZE).unwrap();
    fizzle_shmem.write_to_env("FIZZLE_LIBAFL_RSPBUF").unwrap();
    let fizzle_shmembuf = fizzle_shmem.as_slice_mut();

    let fizzle_resp_observer = unsafe {
        PacketResponseMapObserver::new(StdMapObserver::new("fizzle_responses", fizzle_shmembuf))
    };
    */

    let mut shmem_provider = UnixShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // write the id to the env var for the forkserver
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    env::set_var("AFL_MAP_SIZE", MAP_SIZE.to_string());
    let shmembuf = shmem.as_slice_mut();
    // build an observer based on that buffer shared with the target
    let mut edges_observer = unsafe { HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmembuf)) };

    let map_feedback  = MapFeedback::new(&mut edges_observer);

    let state_observer = StateObserver::<u32>::new("ButterflyState");
    let state_feedback = StateFeedback::new(&state_observer);

    let mut mgr = SimpleEventManager::new(tui_monitor);

    let mut feedback = feedback_or!(
        state_feedback,
        map_feedback,
    );

    let mut objective = feedback_or_fast!(
        CrashFeedback::new(),
        TimeoutFeedback::new(),
    );

    let mut state = StdState::new(
        StdRand::with_seed(0),
        InMemoryCorpus::<Packets<ftp::FtpProtocol>>::new(),
        InMemoryCorpus::new(),
        &mut feedback,
        &mut objective
    ).unwrap();

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let mutator = PacketMutationScheduler::new(
        tuple_list!(
            PacketReorderMutator::new(),
            PacketDeleteMutator::new(4),
            PacketDuplicateMutator::new(16),
            PacketCrossoverInsertMutator::new(),
            PacketCrossoverReplaceMutator::new(),
            PacketSpliceMutator::new(4),
            PacketHavocMutator::new(supported_havoc_mutations()),
        )
    );
    let mut stages = tuple_list!(
        StdMutationalStage::new(mutator)
    );

    let fork_executor = ForkserverExecutor::builder()
        .parse_afl_cmdline(env::args())
        .is_deferred_frksrv(true)
        .is_persistent(true)
        .shmem_provider(&mut shmem_provider)
        .coverage_map_size(MAP_SIZE)
    /*
        .program("whoami")
        .arg("-h")
        .env("LD_PRELOAD", "/fizzle/target/debug/libfizzle.so")
        .min_input_size(1)
        .max_input_size(65536)
        .timeout(Duration::from_secs(2))
    */
        .env("LD_PRELOAD", "/fizzle/target/debug/libfizzle.so")
        .build::<Packets<_>, _, _>(tuple_list!(state_observer, edges_observer)) // , fizzle_resp_observer
        .unwrap();

    let mut fizzle_executor = FizzleExecutor::new(fork_executor);

    // Load corpus
//    load_pcaps(&mut state, &mut fuzzer, &mut fizzle_executor, &mut mgr, "pcaps").unwrap();
    
    // Start the campaign
    // TODO: replace with this to run fuzzing forever
    fuzzer.fuzz_loop(&mut stages, &mut fizzle_executor, &mut state, &mut mgr).unwrap();

    
   
    /*
    fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 50).unwrap();
    
    // Manually print the stategraph
    let observer = executor.observers();
    let state_observer: &StateObserver<u32> = &observer[&Handle::new("ButterflyState".into())];
    println!("{}", state_observer.get_statemachine());
    */
}
