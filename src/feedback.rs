use crate::{
    event::{USER_STAT_EDGES, USER_STAT_NODES},
    observer::StateObserver,
};

#[cfg(feature = "graphviz")]
use crate::event::USER_STAT_STATEGRAPH;

use libafl_bolts::Named;
use libafl::{
    events::{Event, EventFirer},
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    inputs::Input,
    monitors::stats::{AggregatorOps, UserStats, UserStatsValue},
    observers::ObserversTuple,
    state::HasClientPerfMonitor,
    Error,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, cmp::Eq};
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

/// Determines that an input is interesting if it led to new states or transitions in the previous run.
#[derive(Debug)]
pub struct StateFeedback<PS>
where
    PS: Debug + Clone + Eq + Hash + Serialize + for<'a> Deserialize<'a>,
{
    observer_name: String,
    phantom: PhantomData<PS>,
}

impl<PS> StateFeedback<PS>
where
    PS: Debug + Clone + Eq + Hash + Serialize + for<'a> Deserialize<'a>,
{
    /// Create a new StateFeedback from a StateObserver
    pub fn new(observer: &StateObserver<PS>) -> Self {
        Self {
            observer_name: observer.name().to_string(),
            phantom: PhantomData,
        }
    }
}

impl<PS> Named for StateFeedback<PS>
where
    PS: Debug + Clone + Eq + Hash + Serialize + for<'a> Deserialize<'a>,
{
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("StateFeedback")
    }
}

impl<PS, S> StateInitializer<S> for StateFeedback<PS>
where
    PS: Debug + Clone + Eq + Hash + Serialize + for<'a> Deserialize<'a>,
{
    /// Initializes the feedback state.
    /// This method is called after that the `State` is created.
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(()) // TODO: BUG: does this need anything else?
    }
}

/*
impl<PS> HasObserverName for StateFeedback<PS>
where
    PS: Debug + Clone + Eq + Hash + Serialize + for<'a> Deserialize<'a>,
{
    fn observer_name(&self) -> &str {
        &self.observer_name
    }
}
*/

impl<EM, I, OT, S, PS> Feedback<EM, I, OT, S> for StateFeedback<PS>
where
    EM: EventFirer<I, S>,
    I: Input,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor,
    PS: Debug + Clone + Eq + Hash + Serialize + for<'a> Deserialize<'a>,
{
    fn is_interesting(&mut self, state: &mut S, mgr: &mut EM, _input: &I, observers: &OT, _exit_kind: &ExitKind) -> Result<bool, Error>
    {
        let state_observer = observers.match_name::<StateObserver<PS>>(&self.observer_name).unwrap();

        let ret = state_observer.had_new_transitions();

        if ret {
            let (nodes, edges) = state_observer.info();

            mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: Cow::Borrowed(USER_STAT_NODES),
                    value: UserStats::new(UserStatsValue::Number(nodes as u64), AggregatorOps::Max),
                    phantom: PhantomData,
                },
            )?;
            mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: Cow::Borrowed(USER_STAT_EDGES),
                    value: UserStats::new(UserStatsValue::Number(edges as u64), AggregatorOps::Max),
                    phantom: PhantomData,
                },
            )?;

            #[cfg(feature = "graphviz")]
            {
                mgr.fire(
                    state,
                    Event::UpdateUserStats {
                        name: Cow::Borrowed(USER_STAT_STATEGRAPH),
                        value: UserStats::new(UserStatsValue::String(Cow::Owned(state_observer.get_statemachine())), AggregatorOps::None),
                        phantom: PhantomData,
                    },
                )?;
            }
        }

        Ok(ret)
    }
}
