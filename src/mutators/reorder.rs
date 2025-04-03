use crate::input::HasPackets;
use libafl_bolts::{rands::Rand, HasLen, Named};
use libafl::{
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use std::{borrow::Cow, marker::PhantomData, num::NonZero};

/// A mutator that swaps two random packets.
pub struct PacketReorderMutator<P> {
    phantom: PhantomData<P>,
}

impl<P> PacketReorderMutator<P> {
    /// Create a new PacketReorderMutator
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketReorderMutator<P>
where
    I: Input + HasLen + HasPackets<P>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        if input.len() <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(NonZero::new(input.len()).unwrap()) as usize;
        let to = state.rand_mut().below(NonZero::new(input.len()).unwrap()) as usize;

        if from == to {
            return Ok(MutationResult::Skipped);
        }

        input.packets_mut().swap(from, to);

        Ok(MutationResult::Mutated)
    }
}

impl<P> Named for PacketReorderMutator<P> {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("PacketReorderMutator")
    }
}
