use crate::input::HasPackets;
use libafl_bolts::{rands::Rand, HasLen, Named};
use libafl::{
    inputs::{BytesInput, Input},
    mutators::{MutationResult, Mutator},
    state::{HasMaxSize, HasRand},
    Error,
};
use std::{borrow::Cow, marker::PhantomData, num::NonZero};

/// Signifies that a packet type supports the [`PacketCrossoverInsertMutator`] mutator.    
///
/// If you want to use the [`PacketCrossoverInsertMutator`] your Input type must have
/// a vector of packets that implement this trait.    
/// IMPORTANT: This must be implemented on the packet type, not the input type.
///
/// Already implemented for
/// - [`BytesInput`](libafl::inputs::BytesInput)
///
/// # Example
/// Suppose we have the following packet type
/// ```
/// enum PacketType {
///    A(BytesInput),
///    B(BytesInput),
/// }
/// ```
/// Then we can implement this trait as follows
/// ```
/// impl<S> HasCrossoverInsertMutation<S> for PacketType
/// where
///    S: HasRand + HasMaxSize,
/// {
///    fn mutate_crossover_insert(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error> {
///        match self {
///            PacketType::A(data) => {
///                match other {
///                    PacketType::A(other_data) => data.mutate_crossover_insert(state, other_data),
///                    PacketType::B(_) => Ok(MutationResult::Skipped),
///                }
///            },
///            PacketType::B(data) => {
///                match other {
///                    PacketType::A(_) => Ok(MutationResult::Skipped),
///                    PacketType::B(other_data) => data.mutate_crossover_insert(state, other_data),
///                }
///            },
///        }
///    }
/// }
/// ```
/// And now we are able to use the [`PacketCrossoverInsertMutator`].
pub trait HasCrossoverInsertMutation<S>
where
    S: HasRand + HasMaxSize,
{
    /// Perform one crossover mutation where bytes from `other` are inserted into `self`
    ///
    /// The arguments to this function are similar to [`Mutator::mutate()`](libafl::mutators::Mutator::mutate).
    fn mutate_crossover_insert(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error>;
}

impl<S> HasCrossoverInsertMutation<S> for BytesInput
where
    S: HasRand + HasMaxSize,
{
    fn mutate_crossover_insert(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error> {
        if self.len() == 0 || other.len() == 0 {
            return Ok(MutationResult::Skipped);
        }

        let self_len = NonZero::new(self.len()).unwrap();
        let other_len = NonZero::new(other.len()).unwrap();

        let from = state.rand_mut().below(other_len);
        let to = state.rand_mut().below(self_len) as usize;
        let len = state.rand_mut().below(NonZero::new(other.len() - from).unwrap()) as usize + 1;

        // Make room for `len` additional bytes
        self.as_mut().resize(usize::from(self_len) + len, 0);

        // Move bytes at `to` `len` places to the right
        self.as_mut().copy_within(to..self_len.into(), to + len);

        // Insert `from` bytes from `other` into self at index `to`
        self.as_mut()[to..to + len].copy_from_slice(&other.as_ref()[from..from + len]);

        Ok(MutationResult::Mutated)
    }
}

/// Like libafls [`CrossoverInsertMutator`](libafl::mutators::mutations::CrossoverInsertMutator)
/// but for two packets in one seed.
///
/// `P` denotes the type of an individual packet that MUST implement [`HasCrossoverInsertMutation`].
pub struct PacketCrossoverInsertMutator<P, S>
where
    P: HasCrossoverInsertMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    phantom: PhantomData<(P, S)>,
}

impl<P, S> PacketCrossoverInsertMutator<P, S>
where
    P: HasCrossoverInsertMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    /// Create a new PacketCrossoverInsertMutator
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketCrossoverInsertMutator<P, S>
where
    P: HasCrossoverInsertMutation<S> + Clone,
    I: Input + HasLen + HasPackets<P>,
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        if input.len() <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let input_len = NonZero::new(input.len()).unwrap();
        let packet = state.rand_mut().below(input_len) as usize;
        let other = state.rand_mut().below(input_len) as usize;

        if packet == other {
            return Ok(MutationResult::Skipped);
        }

        #[cfg(feature = "safe_only")]
        {
            let other = input.packets()[other].clone();
            input.packets_mut()[packet].mutate_crossover_insert(state, &other)
        }
        #[cfg(not(feature = "safe_only"))]
        {
            let dst = std::ptr::addr_of_mut!(input.packets_mut()[packet]);
            let src = std::ptr::addr_of!(input.packets()[other]);
            unsafe { dst.as_mut().unwrap().mutate_crossover_insert(state, src.as_ref().unwrap()) }
        }
    }
}

impl<P, S> Named for PacketCrossoverInsertMutator<P, S>
where
    P: HasCrossoverInsertMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("PacketCrossoverInsertMutator")
    }
}

/// Signifies that a packet type supports the [`PacketCrossoverReplaceMutator`] mutator.    
///
/// If you want to use the [`PacketCrossoverReplaceMutator`] your Input type must have
/// a vector of packets that implement this trait.    
/// IMPORTANT: This must be implemented on the packet type, not the input type.
///
/// Already implemented for
/// - [`BytesInput`](libafl::inputs::BytesInput)
///
/// # Example
/// Suppose we have the following packet type
/// ```
/// enum PacketType {
///    A(BytesInput),
///    B(BytesInput),
/// }
/// ```
/// Then we can implement this trait as follows
/// ```
/// impl<S> HasCrossoverReplaceMutation<S> for PacketType
/// where
///    S: HasRand + HasMaxSize,
/// {
///    fn mutate_crossover_replace(&mut self, state: &mut S, other: &Self: i32) -> Result<MutationResult, Error> {
///        match self {
///            PacketType::A(data) => {
///                match other {
///                    PacketType::A(other_data) => data.mutate_crossover_replace(state, other_data),
///                    PacketType::B(_) => Ok(MutationResult::Skipped),
///                }
///            },
///            PacketType::B(data) => {
///                match other {
///                    PacketType::A(_) => Ok(MutationResult::Skipped),
///                    PacketType::B(other_data) => data.mutate_crossover_replace(state, other_data),
///                }
///            },
///        }
///    }
/// }
/// ```
/// And now we are able to use the [`PacketCrossoverReplaceMutator`].
pub trait HasCrossoverReplaceMutation<S>
where
    S: HasRand + HasMaxSize,
{
    /// Perform one crossover mutation where bytes in `self` are replaced by bytes from `other`.
    ///
    /// The arguments to this function are similar to [`Mutator::mutate()`](libafl::mutators::Mutator::mutate).
    fn mutate_crossover_replace(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error>;
}

impl<S> HasCrossoverReplaceMutation<S> for BytesInput
where
    S: HasRand + HasMaxSize,
{
    fn mutate_crossover_replace(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error> {
        let self_len = self.len();
        let other_len = other.len();

        if self_len == 0 || other_len == 0 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(NonZero::new(other_len).unwrap());
        let to = state.rand_mut().below(NonZero::new(self_len).unwrap());
        let len = 1 + state.rand_mut().below(NonZero::new(std::cmp::min(other_len - from, self_len - to)).unwrap());

        self.as_mut()[to..to + len].copy_from_slice(&other.as_ref()[from..from + len]);

        Ok(MutationResult::Mutated)
    }
}

/// Like libafls [`CrossoverReplaceMutator`](libafl::mutators::mutations::CrossoverReplaceMutator)
/// but for two packets in one seed.
///
/// `P` denotes the type of an individual packet that MUST implement [`HasCrossoverReplaceMutation`].
pub struct PacketCrossoverReplaceMutator<P, S>
where
    P: HasCrossoverReplaceMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    phantom: PhantomData<(P, S)>,
}

impl<P, S> PacketCrossoverReplaceMutator<P, S>
where
    P: HasCrossoverReplaceMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    /// Create a new PacketCrossoverReplaceMutator
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketCrossoverReplaceMutator<P, S>
where
    P: HasCrossoverReplaceMutation<S> + Clone,
    I: Input + HasLen + HasPackets<P>,
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        if input.len() <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let packet = state.rand_mut().below(NonZero::new(input.len()).unwrap()) as usize;
        let other = state.rand_mut().below(NonZero::new(input.len()).unwrap()) as usize;

        if packet == other {
            return Ok(MutationResult::Skipped);
        }

        #[cfg(feature = "safe_only")]
        {
            let other = input.packets()[other].clone();
            input.packets_mut()[packet].mutate_crossover_replace(state, &other)
        }
        #[cfg(not(feature = "safe_only"))]
        {
            let dst = std::ptr::addr_of_mut!(input.packets_mut()[packet]);
            let src = std::ptr::addr_of!(input.packets()[other]);
            unsafe { dst.as_mut().unwrap().mutate_crossover_replace(state, src.as_ref().unwrap()) }
        }
    }
}

impl<P, S> Named for PacketCrossoverReplaceMutator<P, S>
where
    P: HasCrossoverReplaceMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("PacketCrossoverReplaceMutator")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libafl_bolts::rands::StdRand;
    use libafl::{
        corpus::CorpusId, inputs::BytesInput, mutators::MutationResult, state::{HasMaxSize, HasRand}
    };
    extern crate test;
    use serde::{Deserialize, Serialize};
    use test::Bencher;

    struct TestState {
        rand: StdRand,
        max_size: usize,
    }
    impl TestState {
        fn new() -> Self {
            Self {
                rand: StdRand::with_seed(0),
                max_size: 0,
            }
        }
    }
    impl HasRand for TestState {
        type Rand = StdRand;

        fn rand(&self) -> &StdRand {
            &self.rand
        }

        fn rand_mut(&mut self) -> &mut StdRand {
            &mut self.rand
        }
    }
    impl HasMaxSize for TestState {
        fn max_size(&self) -> usize {
            self.max_size
        }

        fn set_max_size(&mut self, max_size: usize) {
            self.max_size = max_size;
        }
    }

    #[derive(Hash, Debug, Clone, Serialize, Deserialize)]
    struct TestInput {
        packets: Vec<BytesInput>,
    }
    impl Input for TestInput {
        fn generate_name(&self, _id: Option<CorpusId>) -> String {
            todo!();
        }
    }
    impl HasPackets<BytesInput> for TestInput {
        fn packets(&self) -> &[BytesInput] {
            &self.packets
        }

        fn packets_mut(&mut self) -> &mut Vec<BytesInput> {
            &mut self.packets
        }
    }
    impl HasLen for TestInput {
        fn len(&self) -> usize {
            self.packets.len()
        }
    }

    #[test]
    fn test_insert_empty() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(Vec::new());
        let b = BytesInput::new(Vec::new());

        for _ in 0..100 {
            assert_eq!(a.mutate_crossover_insert(&mut state, &b).unwrap(), MutationResult::Skipped);
        }
    }

    #[test]
    fn test_insert_len1() {
        let mut state = TestState::new();
        let b = BytesInput::new(b"B".to_vec());

        for _ in 0..100 {
            let mut a = BytesInput::new(b"A".to_vec());
            assert_eq!(a.mutate_crossover_insert(&mut state, &b).unwrap(), MutationResult::Mutated);
            assert!(a.as_ref() == b"AB" || a.as_ref() == b"BA");
        }
    }

    #[test]
    fn test_insert_resize() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(b"A".to_vec());
        let b = BytesInput::new(b"asdasd fasd fa sdf asdf asdfasfd asdfsadf asdfsadf asdfsa df ".to_vec());

        for _ in 0..100 {
            assert_eq!(a.mutate_crossover_insert(&mut state, &b).unwrap(), MutationResult::Mutated);
        }
    }

    #[test]
    fn test_replace_empty() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(Vec::new());
        let b = BytesInput::new(Vec::new());

        for _ in 0..100 {
            assert_eq!(a.mutate_crossover_replace(&mut state, &b).unwrap(), MutationResult::Skipped);
        }
    }

    #[test]
    fn test_replace_len1() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(b"A".to_vec());
        let b = BytesInput::new(b"B".to_vec());

        for _ in 0..100 {
            assert_eq!(a.mutate_crossover_replace(&mut state, &b).unwrap(), MutationResult::Mutated);
            assert_eq!(a.as_ref(), b"B");
        }
    }

    #[test]
    fn test_replace_resize() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(b"A".to_vec());
        let b = BytesInput::new(b"asdasd fasd fa sdf asdf asdfasfd asdfsadf asdfsadf asdfsa df ".to_vec());

        for _ in 0..100 {
            assert_eq!(a.mutate_crossover_replace(&mut state, &b).unwrap(), MutationResult::Mutated);
        }
    }

    #[test]
    fn test_mutator_insert() {
        let mut state = TestState::new();
        let mut mutator = PacketCrossoverInsertMutator::<BytesInput, TestState>::new();
        let mut input = TestInput {
            packets: vec![BytesInput::new(vec![0; 4096]), BytesInput::new(vec![1; 4096])],
        };

        while mutator.mutate(&mut state, &mut input).unwrap() == MutationResult::Skipped {}

        let mut modified = false;

        for b in input.packets[0].as_ref() {
            if *b == 1 {
                modified = true;
            }
        }
        for b in input.packets[1].as_ref() {
            if *b == 0 {
                modified = true;
            }
        }

        assert!(modified);
        assert!(input.packets[0].len() > 4096 || input.packets[1].len() > 4096);
    }

    #[bench]
    fn bench_mutator_insert(b: &mut Bencher) {
        let mut state = TestState::new();
        let mut mutator = PacketCrossoverInsertMutator::<BytesInput, TestState>::new();
        let mut input = TestInput {
            packets: vec![BytesInput::new(vec![0; 4096]), BytesInput::new(vec![1; 4096])],
        };

        b.iter(|| {
            input.packets[0].as_mut().resize(4096, 0);
            input.packets[1].as_mut().resize(4096, 1);
            while mutator.mutate(&mut state, &mut input).unwrap() == MutationResult::Skipped {}
        });
    }

    #[test]
    fn test_mutator_replace() {
        let mut state = TestState::new();
        let mut mutator = PacketCrossoverReplaceMutator::<BytesInput, TestState>::new();
        let mut input = TestInput {
            packets: vec![BytesInput::new(vec![0; 4096]), BytesInput::new(vec![1; 4096])],
        };

        while mutator.mutate(&mut state, &mut input).unwrap() == MutationResult::Skipped {}

        let mut modified = false;

        for b in input.packets[0].as_ref() {
            if *b == 1 {
                modified = true;
            }
        }
        for b in input.packets[1].as_ref() {
            if *b == 0 {
                modified = true;
            }
        }

        assert!(modified);
    }

    #[bench]
    fn bench_mutator_replace(b: &mut Bencher) {
        let mut state = TestState::new();
        let mut mutator = PacketCrossoverReplaceMutator::<BytesInput, TestState>::new();
        let mut input = TestInput {
            packets: vec![BytesInput::new(vec![0; 4096]), BytesInput::new(vec![1; 4096])],
        };

        b.iter(|| while mutator.mutate(&mut state, &mut input).unwrap() == MutationResult::Skipped {});
    }
}
