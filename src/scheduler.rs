use libafl_bolts::{rands::Rand, Named};
use libafl::{
    inputs::Input,
    mutators::{ComposedByMutations, MutationId, MutationResult, Mutator, MutatorsTuple, ScheduledMutator},
    state::HasRand,
    Error,
};
use std::{borrow::Cow, marker::PhantomData, num::NonZero};

/// A mutation scheduler for butterflys mutators.
///
/// It schedules them in such a way that only one mutator in the list
/// gets executed per run because the mutators may implement their own scheduling,
/// like the [`PacketHavocMutator`](crate::PacketHavocMutator), which stacks
/// havoc mutations on its own.
pub struct PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    mutations: MT,
    phantom: PhantomData<(I, S)>,
}

impl<I, MT, S> PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Create a new PacketMutationScheduler with a list of mutators.
    /// These mutators _should_ be from butterfly.   
    /// It is not guaranteed that external mutators will work too.
    pub fn new(mutations: MT) -> Self {
        Self {
            mutations,
            phantom: PhantomData,
        }
    }
}

impl<I, MT, S> ComposedByMutations for PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    type Mutations = MT;

    fn mutations(&self) -> &Self::Mutations {
        &self.mutations
    }

    fn mutations_mut(&mut self) -> &mut MT {
        &mut self.mutations
    }
}

impl<I, MT, S> Named for PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("PacketMutationScheduler")
    }
}

impl<I, MT, S> Mutator<I, S> for PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input)
    }
}

impl<I, MT, S> ScheduledMutator<I, S> for PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn iterations(&self, _state: &mut S, _input: &I) -> u64 {
        1
    }

    fn schedule(&self, state: &mut S, _input: &I) -> MutationId {
        MutationId::from(
            state.rand_mut().below(NonZero::new(self.mutations.len()).unwrap()) as usize
        )
    }

    fn scheduled_mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let mut result = MutationResult::Skipped;

        while result == MutationResult::Skipped {
            let mutation = self.schedule(state, input);
            result = self.mutations.get_and_mutate(mutation, state, input)?;
        }

        Ok(result)
    }
}
