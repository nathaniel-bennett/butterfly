use std::fmt::Debug;
use std::hash::Hash;
use std::io::Read;

use butterfly::{HasCrossoverInsertMutation, HasCrossoverReplaceMutation, HasHavocMutation, HasPackets, HasPcapRepresentation, HasSpliceMutation};
use libafl::{inputs::{BytesInput, HasTargetBytes, Input}, mutators::{MutationId, MutationResult, MutatorsTuple}, state::{HasMaxSize, HasRand}};
use libafl_bolts::{generic_hash_std, ownedref::OwnedSlice, HasLen};
use serde::{Deserialize, Serialize};

#[derive(Clone, serde::Deserialize, Debug, Hash, serde::Serialize)]
pub struct Packets<P: PacketProtocol> {
    pkts: Vec<P>,
}

impl<P: PacketProtocol> Packets<P> {
    pub fn packets(&self) -> &[P] {
        self.pkts.as_slice()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(self.pkts.len() as u32).to_be_bytes());

        for pkt in &self.pkts {
            let len_field_start = v.len();
            v.extend_from_slice(&0u32.to_be_bytes());
            pkt.to_bytes_extend(&mut v);
            let len = v.len() - (len_field_start + 4);
            v[len_field_start..len_field_start + 4].copy_from_slice(&len.to_be_bytes());
        }

        v
    }

    /*
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, libafl::Error> {
        let num_records = u32::from_be_bytes(bytes.get(..4).ok_or(libafl::Error::invalid_corpus("deserializing corpus input failed"))?.try_into().unwrap());
        
        let mut pkts = Vec::new();

        let mut idx = 4;
        for _ in 0..num_records {
            let record_len = u32::from_be_bytes(bytes.get(idx..idx + 4).ok_or(libafl::Error::invalid_corpus("deserializing corpus input failed"))?.try_into().unwrap()) as usize;
            idx += 4;
            let pkt = P::from_bytes(bytes.get(idx..idx + record_len).ok_or(libafl::Error::invalid_corpus("deserializing corpus input failed"))?).ok_or(libafl::Error::invalid_corpus("deserializing corpus input failed"))?;
            idx += record_len;
            pkts.push(pkt);
        }

        if idx < bytes.len() {
            return Err(libafl::Error::invalid_corpus("excess bytes at end of corpus deserialization"))
        }

        Ok(Self {
            pkts,
        })
    }
    */
}

impl<P> Input for Packets<P>
where 
    P: PacketProtocol + for<'a> Deserialize<'a>
{
    fn generate_name(&self, _id: Option<libafl::corpus::CorpusId>) -> String {
        std::format!("{:016x}", generic_hash_std(self))
    }
}

impl<P> HasPackets<P> for Packets<P>
where 
    P: PacketProtocol
{
    fn packets(&self) -> &[P] {
        self.pkts.as_slice()
    }

    fn packets_mut(&mut self) -> &mut Vec<P> {
        &mut self.pkts
    }
}

impl<P> HasLen for Packets<P>
where 
    P: PacketProtocol
{
    fn len(&self) -> usize {
        self.pkts.len()
    }
}

impl<P> HasTargetBytes for Packets<P>
where 
    P: PacketProtocol
{
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(self.to_bytes())
    }
}

impl<P> HasPcapRepresentation<Packets<P>> for Packets<P>
where 
    P: PacketProtocol
{
    fn from_pcap(capture: pcap::Capture<pcap::Offline>) -> Result<Packets<P>, libafl::Error> {
        let pkts = P::from_pcap(capture).unwrap();
        
        Ok(Packets {
            pkts
        })
    }
}

pub trait PacketProtocol: Clone + Debug + Hash + serde::Serialize {
    type Parser: ProtoParser;

    fn to_bytes_extend(&self, v: &mut Vec<u8>);

    fn from_pcap(capture: pcap::Capture<pcap::Offline>) -> Option<Vec<Self>>;

    fn parse_request(p: &mut Self::Parser, req: &Self) -> Option<u32> {
        unimplemented!()
    }

    fn parse_response(p: &mut Self::Parser, resp: &[u8]) -> Option<u32> {
        unimplemented!()
    }
}

pub trait ProtoParser {
    fn new() -> Self;
}

#[derive(Clone, Debug, Hash, serde::Serialize, serde::Deserialize)]
pub enum OpaqueProtocol {
    Opaque(BytesInput),
}

impl OpaqueProtocol {
    pub fn inner_data(&self) -> Option<&BytesInput> {
        match self {
            Self::Opaque(v) => Some(v),
        }
    }

    pub fn inner_data_mut(&mut self) -> Option<&mut BytesInput> {
        match self {
            Self::Opaque(v) => Some(v),
        }
    }
}

impl PacketProtocol for OpaqueProtocol {
    type Parser = OpaqueParser;

    fn to_bytes_extend(&self, v: &mut Vec<u8>) {
        match self {
            Self::Opaque(i) => v.extend_from_slice(i.as_ref()), 
        }
    }

    fn from_pcap(capture: pcap::Capture<pcap::Offline>) -> Option<Vec<Self>> {
        Some(Vec::new()) // TODO: unimplemented
    }
}

impl<S> HasCrossoverInsertMutation<S> for OpaqueProtocol
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

impl<S> HasCrossoverReplaceMutation<S> for OpaqueProtocol
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

impl<S> HasSpliceMutation<S> for OpaqueProtocol
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

impl<MT, S> HasHavocMutation<MT, S> for OpaqueProtocol 
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

pub struct OpaqueParser {

}

impl ProtoParser for OpaqueParser {
    fn new() -> Self {
        Self {

        }
    }
}
