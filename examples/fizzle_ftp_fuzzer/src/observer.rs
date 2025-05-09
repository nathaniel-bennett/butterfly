use std::borrow::Cow;

use libafl::observers::{Observer, StdMapObserver};
use libafl_bolts::{tuples::MatchName, Named};

pub const PKT_RSP_MAP_NAME: &str = "PacketResponseMapObserver";

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PacketResponseMapObserver<'a> {
    base: StdMapObserver<'a, u8, false>,
    index: usize,
    remaining: Option<usize>,
}

impl<'a> PacketResponseMapObserver<'a> {
    /// Creates a new [`MapObserver`]
    pub fn new(base: StdMapObserver<'a, u8, false>) -> Self {
        Self {
            base,
            index: 0,
            remaining: None,
        }
    }

    // TODO: implement response state inferrence later
    /*
    pub fn next_response(&'a self) -> Option<&'a [u8]> {

    }

    pub fn responses(&'a self) -> Vec<&'a [u8]> {
        let resp_cnt = u32::from_be_bytes(self.base.get(..4).unwrap().try_into().unwrap()) as usize;

        let mut responses = Vec::new();

        let mut idx = 4;
        for _ in 0..resp_cnt {
            let len = u32::from_be_bytes(self.base.get(idx..idx + 4).unwrap().try_into().unwrap()) as usize;
            idx += 4;
            let pkt = self.base.get(idx..idx + len).unwrap();
            responses.push(pkt);
        }

        responses
    }
    */
}

impl Named for PacketResponseMapObserver<'_> {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        &Cow::Borrowed(PKT_RSP_MAP_NAME)
    }
}

impl<'a> MatchName for PacketResponseMapObserver<'a> 
where
{
    fn match_name<T>(&self, name: &str) -> Option<&T> {
        if name == PKT_RSP_MAP_NAME {
            Some(unsafe { &*std::ptr::from_ref(self).cast() })
        } else {
            None
        }
    }
    
    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T> {
        if name == PKT_RSP_MAP_NAME {
            Some(unsafe { &mut *std::ptr::from_mut(self).cast() })
        } else {
            None
        }
    }
}

impl<'a, I, S> Observer<I, S> for PacketResponseMapObserver<'a> {
    fn flush(&mut self) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn pre_exec_child(&mut self, _state: &mut S, _input: &I) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}
