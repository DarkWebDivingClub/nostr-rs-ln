//! BTree with configurable capacity limits and overflow policies.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use core::cmp::Ordering;
use core::num::NonZeroUsize;

mod set;

pub use self::set::*;

/// Represents the possible options for removing a value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OverCapacityPolicy {
    /// Pop first value
    #[default]
    First,
    /// Pop last value
    Last,
}

/// Represents the possible options for the capacity of the set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Capacity {
    /// Unbounded capacity
    #[default]
    Unbounded,
    /// Bounded capacity
    Bounded {
        /// Maximum capacity
        max: NonZeroUsize,
        /// Overflow policy
        policy: OverCapacityPolicy,
    },
}

impl PartialOrd for Capacity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Capacity {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Unbounded, Self::Unbounded) => Ordering::Equal,
            (Self::Unbounded, Self::Bounded { .. }) => Ordering::Greater,
            (Self::Bounded { .. }, Self::Unbounded) => Ordering::Less,
            (Self::Bounded { max: this_max, .. }, Self::Bounded { max: other_max, .. }) => {
                this_max.cmp(other_max)
            }
        }
    }
}

impl Capacity {
    /// Create a new bounded capacity with default [`OverCapacityPolicy`].
    #[inline]
    pub fn bounded(max: NonZeroUsize) -> Self {
        Self::Bounded {
            max,
            policy: OverCapacityPolicy::default(),
        }
    }
}
