use ahash::RandomState;
use libafl_bolts::tuples::MatchName;
use libafl_bolts::Named;
use libafl::{executors::ExitKind, observers::Observer, Error};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cmp::Eq;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Write};
use std::hash::Hash;

#[inline]
fn pack_transition(from: u32, to: u32) -> u64 {
    (from as u64) << 32 | (to as u64)
}

#[inline]
fn unpack_transition(transition: u64) -> (u32, u32) {
    ((transition >> 32) as u32, transition as u32)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "PS: serde::Serialize + for<'a> serde::Deserialize<'a>")]
struct StateGraph<PS>
where
    PS: Clone + Debug + Eq + Hash,
{
    nodes: HashMap<PS, u32, RandomState>,
    edges: HashSet<u64, RandomState>,
    last_node: Option<u32>,
    new_transitions: bool,
}
impl<PS> StateGraph<PS>
where
    PS: Clone + Debug + Eq + Hash + Serialize + for<'a> Deserialize<'a>,
{
    fn new() -> Self {
        Self {
            nodes: HashMap::<PS, u32, RandomState>::default(),
            edges: HashSet::<u64, RandomState>::default(),
            last_node: None,
            new_transitions: false,
        }
    }

    fn reset(&mut self) {
        self.last_node = None;
        self.new_transitions = false;
    }

    fn add_node(&mut self, state: &PS) -> u32 {
        match self.nodes.get(state) {
            Some(id) => *id,
            None => {
                let next_id = self.nodes.len() as u32;
                assert!(self.nodes.insert(state.clone(), next_id).is_none());
                next_id
            },
        }
    }

    fn add_edge(&mut self, id: u32) {
        self.new_transitions |= match self.last_node.take() {
            Some(old_id) => {
                if old_id != id {
                    self.edges.insert(pack_transition(old_id, id))
                } else {
                    false
                }
            },
            None => false,
        };

        self.last_node = Some(id);
    }

    fn write_dot<S>(&self, stream: &mut S)
    where
        S: Write,
    {
        let _ = write!(stream, "digraph IMPLEMENTED_STATE_MACHINE {{");

        for value in &self.edges {
            let (from, to) = unpack_transition(*value);
            let _ = write!(stream, "\"{}\"->\"{}\";", from, to);
        }

        let _ = write!(stream, "}}");
    }
}

/// An observer that builds a state-graph.
///
/// The states that this observer stores must implement
/// the following traits: [`Eq`](core::cmp::Eq), [`Hash`](std::hash::Hash), [`Debug`](core::fmt::Debug), [`Clone`](core::clone::Clone), [`Serialize`](serde::Serialize), [`Deserialize`](serde::Deserialize).
/// Most commonly used state types are u64, u32 or [u8; N] with N <= 32.
///
/// When you create a StateObserver always specify `PS` manually:
/// ```
/// type State = u64;
/// let observer = StateObserver::<State>::new("state observer");
/// ```
///
/// The executor is responsible for calling [`StateObserver::record()`](crate::StateObserver::record)
/// with states inferred from the fuzz target.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "PS: serde::Serialize + for<'a> serde::Deserialize<'a>")]
pub struct StateObserver<PS>
where
    PS: Clone + Debug + Eq + Hash,
{
    name: Cow<'static, str>,
    graph: StateGraph<PS>,
}

impl<PS> StateObserver<PS>
where
    PS: Clone + Debug + Eq + Hash + Serialize + for<'a> Deserialize<'a>,
{
    /// Create a new StateObserver with a given name.
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::Borrowed(name),
            graph: StateGraph::<PS>::new(),
        }
    }

    /// Tell the observer that the target has entered state `state`.
    pub fn record(&mut self, state: &PS) {
        let node = self.graph.add_node(state);
        self.graph.add_edge(node);
    }

    /// Returns whether any new edges were created in the state-graph during the last run.
    /// Used by [`StateFeedback`](crate::StateFeedback).
    pub fn had_new_transitions(&self) -> bool {
        self.graph.new_transitions
    }

    /// Returns the number of vertices and edges in the state-graph.
    /// Used by [`StateFeedback`](crate::StateFeedback).
    pub fn info(&self) -> (usize, usize) {
        (self.graph.nodes.len(), self.graph.edges.len())
    }

    /// Returns a DOT representation of the statemachine.
    pub fn get_statemachine(&self) -> String {
        let mut s = String::with_capacity(1024);
        self.graph.write_dot(&mut s);
        s
    }
}

impl<PS> Named for StateObserver<PS>
where
    PS: Clone + Debug + Hash + Eq + Serialize + for<'a> Deserialize<'a>,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<PS> MatchName for StateObserver<PS> 
where
    PS: Clone + Debug + Hash + Eq + Serialize + for<'a> Deserialize<'a>
{
    fn match_name<T>(&self, name: &str) -> Option<&T> {
        if self.name == name {
            Some(unsafe { &*std::ptr::from_ref(self).cast() })
        } else {
            None
        }
    }
    
    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T> {
        if self.name == name {
            Some(unsafe { &mut *std::ptr::from_mut(self).cast() })
        } else {
            None
        }
    }
}

impl<PS, I, S> Observer<I, S> for StateObserver<PS>
where
    PS: Clone + Debug + Hash + Eq + Serialize + for<'a> Deserialize<'a>,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.graph.reset();
        Ok(())
    }

    fn post_exec(&mut self, _state: &mut S, _input: &I, _exit_kind: &ExitKind) -> Result<(), Error> {
        Ok(())
    }
}

/*
#[cfg(test)]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::Bencher;

    type State = [u8; 32];

    fn state(n: usize) -> State {
        let mut state = State::default();
        state[0..8].copy_from_slice(&n.to_le_bytes());
        state
    }

    #[bench]
    fn bench_duplicates(b: &mut Bencher) {
        let mut graph = StateGraph::<State>::new();
        b.iter(|| {
            let node = graph.add_node(&State::default());
            graph.add_edge(node);
        });
    }

    #[bench]
    fn bench_insertions(b: &mut Bencher) {
        let mut graph = StateGraph::<State>::new();
        let mut i: usize = 0;
        b.iter(|| {
            let node = graph.add_node(&state(i));
            graph.add_edge(node);
            i += 1;
        });
    }

    #[bench]
    #[ignore]
    fn memory_footprint(_: &mut Bencher) {
        let mut graph = StateGraph::<State>::new();
        let limit: usize = 24576;

        for i in 0..limit {
            let i_node = graph.add_node(&state(i));

            for j in 0..limit {
                let j_node = graph.add_node(&state(j));
                graph.add_edge(i_node);
                graph.add_edge(j_node);
                graph.reset();
            }
        }

        println!("nodes = {}", graph.nodes.len());
        println!("edges = {}", graph.edges.len());

        loop {}
    }
}
*/