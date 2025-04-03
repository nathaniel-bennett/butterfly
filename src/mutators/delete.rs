use crate::input::HasPackets;
use libafl_bolts::{rands::Rand, HasLen, Named};
use libafl::{
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::{HasMaxSize, HasRand},
    Error,
};
use std::{borrow::Cow, marker::PhantomData, num::NonZero};

/// A mutator that deletes a single, random packet.
///
/// It respects a lower bound on the number of packets
/// passed as an argument to the constructor.
///
/// # Example
/// ```
/// // Make sure that we always have at least 4 packets in an input
/// let mutator = PacketDeleteMutator::new(4);
/// ```
pub struct PacketDeleteMutator<P> {
    phantom: PhantomData<P>,
    min_packets: usize,
}

impl<P> PacketDeleteMutator<P> {
    /// Create a new PacketDeleteMutator with a lower bound on the number of packets
    pub fn new(min_packets: usize) -> Self {
        Self {
            phantom: PhantomData,
            min_packets: std::cmp::max(1, min_packets),
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketDeleteMutator<P>
where
    I: Input + HasLen + HasPackets<P>,
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        if input.len() <= self.min_packets {
            return Ok(MutationResult::Skipped);
        }

        let idx = state.rand_mut().below(NonZero::new(input.len()).unwrap()) as usize;
        input.packets_mut().remove(idx);

        Ok(MutationResult::Mutated)
    }
}

impl<P> Named for PacketDeleteMutator<P> {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("PacketDeleteMutator")
    }
}
