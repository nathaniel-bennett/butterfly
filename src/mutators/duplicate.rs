use crate::input::HasPackets;
use libafl_bolts::{rands::Rand, HasLen, Named};
use libafl::{
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use std::{borrow::Cow, marker::PhantomData, num::NonZero};

/// A mutator that duplicates a single, random packet.
///
/// It respects an upper bound on the number of packets
/// passed as an argument to the constructor.
///
/// # Example
/// ```
/// // Make sure that we never exceed 16 packets in an input
/// let mutator = PacketDuplicateMutator::new(16);
/// ```
pub struct PacketDuplicateMutator<P>
where
    P: Clone,
{
    max_packets: usize,
    phantom: PhantomData<P>,
}

impl<P> PacketDuplicateMutator<P>
where
    P: Clone,
{
    /// Create a new PacketDuplicateMutator with an upper bound on the number of packets
    pub fn new(max_packets: usize) -> Self {
        Self {
            max_packets,
            phantom: PhantomData,
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketDuplicateMutator<P>
where
    P: Clone,
    I: Input + HasLen + HasPackets<P>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        if input.len() >= self.max_packets {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(NonZero::new(input.len()).unwrap()) as usize;
        let to = state.rand_mut().below(NonZero::new(input.len() + 1).unwrap()) as usize;

        if from == to {
            return Ok(MutationResult::Skipped);
        }

        let copy = input.packets()[from].clone();
        input.packets_mut().insert(to, copy);

        Ok(MutationResult::Mutated)
    }
}

impl<P> Named for PacketDuplicateMutator<P>
where
    P: Clone,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("PacketDuplicateMutator")
    }
}
