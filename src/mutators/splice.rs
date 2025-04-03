use crate::input::HasPackets;
use libafl_bolts::{rands::Rand, HasLen, Named};
use libafl::{
    inputs::{BytesInput, Input},
    mutators::{MutationResult, Mutator},
    state::{HasMaxSize, HasRand},
    Error,
};
use std::{borrow::Cow, marker::PhantomData, num::NonZero};

/// Signifies that a packet type supports the [`PacketSpliceMutator`] mutator.
///
/// If you want to use the [`PacketSpliceMutator`] your Input type must have a vector
/// of packets that implement this trait.      
/// IMPORTANT: This must be implemented on the packet type, NOT the Input type.
///
/// Already implemented for:
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
/// impl<S> HasSpliceMutation<S> for PacketType
/// where
///    S: HasRand + HasMaxSize,
/// {
///    fn mutate_splice(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error> {
///        match self {
///            PacketType::A(data) => {
///                match other {
///                    PacketType::A(other_data) => data.mutate_splice(state, other_data),
///                    PacketType::B(_) => Ok(MutationResult::Skipped),
///                }
///            },
///            PacketType::B(data) => {
///                match other {
///                    PacketType::A(_) => Ok(MutationResult::Skipped),
///                    PacketType::B(other_data) => data.mutate_splice(state, other_data),
///                }
///            },
///        }
///    }
/// }
/// ```
/// And now we are able to use the [`PacketSpliceMutator`].
pub trait HasSpliceMutation<S>
where
    S: HasRand + HasMaxSize,
{
    /// Perform one splicing mutation where `self` and `other` get spliced together at a random midpoint.
    ///
    /// The arguments to this function are similar to [`Mutator::mutate()`](libafl::mutators::Mutator::mutate).
    fn mutate_splice(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error>;
}

impl<S> HasSpliceMutation<S> for BytesInput
where
    S: HasRand + HasMaxSize,
{
    fn mutate_splice(&mut self, state: &mut S, other: &Self) -> Result<MutationResult, Error> {
        let self_len = self.len();
        let other_len = other.len();

        if self_len == 0 || other_len == 0 {
            return Ok(MutationResult::Skipped);
        }

        let to = state.rand_mut().below(NonZero::new(self_len).unwrap()) as usize;
        let from = state.rand_mut().below(NonZero::new(other_len).unwrap()) as usize;
        let len = other_len - from;

        // Make sure we have enough space for all the bytes from `other`
        if to + len > self_len {
            self.as_mut().resize(to + len, 0);
        }

        self.as_mut()[to..to + len].copy_from_slice(&other.as_ref()[from..from + len]);

        Ok(MutationResult::Mutated)
    }
}

/// A mutator that splices two random packets together.
///
/// `P` denotes the type of an individual packet that MUST implement [`HasSpliceMutation`].
/// PacketSpliceMutator respects a lower bound on the number of packets
/// passed as an argument to the constructor.
///
/// # Example
/// ```
/// // Make sure that we always have at least 4 packets
/// let mutator = PacketSpliceMutator::new(4);
/// ```
pub struct PacketSpliceMutator<P, S>
where
    P: HasSpliceMutation<S>,
    S: HasRand + HasMaxSize,
{
    phantom: PhantomData<(P, S)>,
    min_packets: usize,
}

impl<P, S> PacketSpliceMutator<P, S>
where
    P: HasSpliceMutation<S>,
    S: HasRand + HasMaxSize,
{
    /// Create a new PacketSpliceMutator with a lower bound for the number of packets
    pub fn new(min_packets: usize) -> Self {
        Self {
            phantom: PhantomData,
            min_packets: std::cmp::max(1, min_packets),
        }
    }
}

impl<I, P, S> Mutator<I, S> for PacketSpliceMutator<P, S>
where
    P: HasSpliceMutation<S>,
    S: HasRand + HasMaxSize,
    I: Input + HasLen + HasPackets<P>,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        if input.len() <= self.min_packets {
            return Ok(MutationResult::Skipped);
        }

        let packet = state.rand_mut().below(NonZero::new(input.len() - 1).unwrap()) as usize;
        let other = input.packets_mut().remove(packet + 1);

        let ret = input.packets_mut()[packet].mutate_splice(state, &other)?;

        if ret == MutationResult::Skipped {
            input.packets_mut().insert(packet + 1, other);
        }

        Ok(ret)
    }
}

impl<P, S> Named for PacketSpliceMutator<P, S>
where
    P: HasSpliceMutation<S>,
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("PacketSpliceMutator")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libafl_bolts::rands::StdRand;
    use libafl::{
        inputs::BytesInput,
        mutators::MutationResult,
        state::{HasMaxSize, HasRand},
    };

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

    #[test]
    fn test_splice_empty() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(Vec::new());
        let b = BytesInput::new(Vec::new());

        for _ in 0..100 {
            assert_eq!(a.mutate_splice(&mut state, &b).unwrap(), MutationResult::Skipped);
        }
    }

    #[test]
    fn test_splice_len1() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(b"A".to_vec());
        let b = BytesInput::new(b"B".to_vec());

        for _ in 0..100 {
            assert_eq!(a.mutate_splice(&mut state, &b).unwrap(), MutationResult::Mutated);
            assert_eq!(a.as_ref(), b"B");
        }
    }

    #[test]
    fn test_splice_resize() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(b"A".to_vec());
        let b = BytesInput::new(b"asdasd fasd fa sdf asdf asdfasfd asdfsadf asdfsadf asdfsa df ".to_vec());

        for _ in 0..100 {
            assert_eq!(a.mutate_splice(&mut state, &b).unwrap(), MutationResult::Mutated);
        }
    }
}
