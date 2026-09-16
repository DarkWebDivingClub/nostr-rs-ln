//! BTreeSet with configurable capacity limits and overflow policies.

use alloc::collections::btree_set::{IntoIter, Iter};
use alloc::collections::BTreeSet;
use core::borrow::Borrow;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::num::NonZeroUsize;

use crate::{Capacity, OverCapacityPolicy};

/// Result of [`BTreeCapSet::insert`].
#[derive(Debug, Clone)]
pub struct Insert<T> {
    /// Return if the value was inserted or not
    pub inserted: bool,
    /// The removed value
    pub pop: Option<T>,
}

/// BTreeSet with configurable capacity limits and overflow policies.
#[derive(Debug, Clone)]
pub struct BTreeCapSet<T> {
    set: BTreeSet<T>,
    capacity: Capacity,
}

impl<T> Default for BTreeCapSet<T>
where
    T: Ord,
{
    /// Create a new unbounded set.
    #[inline]
    fn default() -> Self {
        Self::unbounded()
    }
}

impl<T> PartialEq for BTreeCapSet<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.set == other.set
    }
}

impl<T> Eq for BTreeCapSet<T> where T: Eq {}

impl<T> PartialOrd for BTreeCapSet<T>
where
    T: PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.set.partial_cmp(&other.set)
    }
}

impl<T> Ord for BTreeCapSet<T>
where
    T: Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.set.cmp(&other.set)
    }
}

impl<T> Hash for BTreeCapSet<T>
where
    T: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.set.hash(state);
    }
}

impl<T> BTreeCapSet<T>
where
    T: Ord,
{
    /// Create a new set with specified capacity
    #[inline]
    pub const fn with_capacity(capacity: Capacity) -> Self {
        Self {
            set: BTreeSet::new(),
            capacity,
        }
    }

    /// Create a new bounded set with default [`OverCapacityPolicy`].
    #[inline]
    pub fn bounded(max: NonZeroUsize) -> Self {
        Self::with_capacity(Capacity::bounded(max))
    }

    /// Create a new unbounded set.
    #[inline]
    pub const fn unbounded() -> Self {
        Self::with_capacity(Capacity::Unbounded)
    }

    /// Get capacity
    #[inline]
    pub const fn capacity(&self) -> Capacity {
        self.capacity
    }

    /// Change capacity
    pub fn change_capacity(&mut self, capacity: Capacity) {
        match capacity {
            // Bounded capacity and limit reached
            Capacity::Bounded { max, policy } if self.set.len() > max.get() => {
                while self.set.len() != max.get() {
                    match policy {
                        OverCapacityPolicy::First => self.set.pop_first(),
                        OverCapacityPolicy::Last => self.set.pop_last(),
                    };
                }
            }
            // Unbounded capacity or bounded capacity not reached
            _ => self.capacity = capacity,
        }
    }

    /// Returns the number of elements in the set.
    ///
    /// # Examples
    ///
    /// ```
    /// use btreecap::BTreeCapSet;
    ///
    /// let mut v = BTreeCapSet::unbounded();
    /// assert_eq!(v.len(), 0);
    /// v.insert(1);
    /// assert_eq!(v.len(), 1);
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Returns `true` if the set contains no elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use btreecap::BTreeCapSet;
    ///
    /// let mut v = BTreeCapSet::unbounded();
    /// assert!(v.is_empty());
    /// v.insert(1);
    /// assert!(!v.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Returns `true` if the set contains an element equal to the value.
    ///
    /// The value may be any borrowed form of the set's element type,
    /// but the ordering on the borrowed form *must* match the
    /// ordering on the element type.
    #[inline]
    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: Borrow<Q> + Ord,
        Q: Ord,
    {
        self.set.contains(value)
    }

    /// Insert value
    ///
    /// If the capacity is full, pop and return the last value.
    pub fn insert(&mut self, value: T) -> Insert<T> {
        // Check capacity
        match self.capacity {
            // Bounded capacity and limit reached
            Capacity::Bounded { max, policy } if self.set.len() >= max.get() => {
                // Get the last value and compare it to the new value without popping
                let should_insert: bool = match policy {
                    OverCapacityPolicy::First => match self.set.first() {
                        Some(first) => &value > first,
                        None => true,
                    },
                    OverCapacityPolicy::Last => match self.set.last() {
                        Some(last) => &value < last,
                        None => true,
                    },
                };

                if should_insert {
                    // Pop the value if the new value should be inserted
                    Insert {
                        inserted: self.set.insert(value),
                        pop: match policy {
                            OverCapacityPolicy::First => self.set.pop_first(),
                            OverCapacityPolicy::Last => self.set.pop_last(),
                        },
                    }
                } else {
                    Insert {
                        inserted: false,
                        pop: None,
                    }
                }
            }
            // Unbounded capacity or bounded capacity not reached
            _ => {
                // Insert value
                Insert {
                    inserted: self.set.insert(value),
                    pop: None,
                }
            }
        }
    }

    /// Force insert the value
    ///
    /// If the capacity is full, automatically increases the capacity.
    pub fn force_insert(&mut self, value: T) -> Insert<T> {
        let inserted: bool = self.set.insert(value);

        // If successfully inserted, check if the capacity must be increased
        if inserted {
            if let Capacity::Bounded { max, .. } = self.capacity {
                let max: usize = max.get();

                if self.set.len() >= max {
                    let new_max: usize = max.saturating_add(1);
                    let new_max: NonZeroUsize =
                        NonZeroUsize::new(new_max).expect("BUG: new_max must be non-zero");
                    self.capacity = Capacity::bounded(new_max);
                }
            }
        }

        // Insert value
        Insert {
            inserted,
            pop: None,
        }
    }

    /// Extend with values
    pub fn extend<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = T>,
    {
        match self.capacity {
            Capacity::Bounded { .. } => {
                // TODO: find more efficient way
                for value in values.into_iter() {
                    self.insert(value);
                }
            }
            Capacity::Unbounded => {
                self.set.extend(values);
            }
        }
    }

    /// If the set contains an element equal to the value, removes it from the
    /// set and drops it. Returns whether such an element was present.
    ///
    /// The value may be any borrowed form of the set's element type,
    /// but the ordering on the borrowed form *must* match the
    /// ordering on the element type.
    ///
    /// # Examples
    ///
    /// ```
    /// use btreecap::BTreeCapSet;
    ///
    /// let mut set = BTreeCapSet::unbounded();
    ///
    /// set.insert(2);
    /// assert_eq!(set.remove(&2), true);
    /// assert_eq!(set.remove(&2), false);
    /// ```
    #[inline]
    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        T: Borrow<Q> + Ord,
        Q: Ord,
    {
        self.set.remove(value)
    }

    /// Get first value
    #[inline]
    pub fn first(&self) -> Option<&T>
    where
        T: Ord,
    {
        self.set.first()
    }

    /// Get last value
    #[inline]
    pub fn last(&self) -> Option<&T>
    where
        T: Ord,
    {
        self.set.last()
    }

    /// Gets an iterator that visits the elements in ascending order.
    #[inline]
    pub fn iter(&self) -> Iter<'_, T> {
        self.set.iter()
    }
}

impl<T> From<BTreeSet<T>> for BTreeCapSet<T> {
    /// Convert from [`BTreeSet`] and set capacity to unbounded.
    fn from(set: BTreeSet<T>) -> Self {
        Self {
            set,
            capacity: Capacity::Unbounded,
        }
    }
}

impl<T> IntoIterator for BTreeCapSet<T> {
    type Item = T;
    type IntoIter = IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.set.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert() {
        let mut set = BTreeCapSet::bounded(NonZeroUsize::new(2).unwrap());

        let res = set.insert(1);
        assert!(res.inserted);
        assert!(res.pop.is_none());
        assert_eq!(set.len(), 1);

        let res = set.insert(2);
        assert!(res.inserted);
        assert!(res.pop.is_none());
        assert_eq!(set.len(), 2);

        // exceeds capacity, 1 is removed
        let res = set.insert(3);
        assert!(res.inserted);
        assert_eq!(res.pop, Some(1));
        assert_eq!(set.len(), 2);

        // try to re-insert 1
        let res = set.insert(1);
        assert!(!res.inserted); // NOT inserted (cap reached)
        assert_eq!(res.pop, None);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_insert_inverted() {
        let mut set = BTreeCapSet::with_capacity(Capacity::Bounded {
            max: NonZeroUsize::new(2).unwrap(),
            policy: OverCapacityPolicy::Last,
        });

        let res = set.insert(1);
        assert!(res.inserted);
        assert!(res.pop.is_none());
        assert_eq!(set.len(), 1);

        let res = set.insert(2);
        assert!(res.inserted);
        assert!(res.pop.is_none());
        assert_eq!(set.len(), 2);

        // exceeds capacity, 2 is removed
        let res = set.insert(0);
        assert!(res.inserted);
        assert_eq!(res.pop, Some(2));
        assert_eq!(set.len(), 2);

        // try to insert 3
        let res = set.insert(3);
        assert!(!res.inserted); // NOT inserted (cap reached and inverted policy)
        assert_eq!(res.pop, None);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_remove() {
        let mut set = BTreeCapSet::bounded(NonZeroUsize::new(3).unwrap());
        set.insert(1);
        set.insert(2);
        set.insert(3);

        assert!(set.remove(&1));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_change_capacity() {
        let mut set = BTreeCapSet::bounded(NonZeroUsize::new(3).unwrap());
        set.insert(1);
        set.insert(2);
        set.insert(3);

        // resize, discarding elements to cap the capacity
        set.change_capacity(Capacity::bounded(NonZeroUsize::new(2).unwrap()));

        // 1 has been discarded due to resize
        assert_eq!(set.len(), 2);
        assert!(!set.remove(&1));
    }

    #[test]
    fn test_iter() {
        let mut set = BTreeCapSet::bounded(NonZeroUsize::new(3).unwrap());
        set.insert(1);
        set.insert(2);
        set.insert(3);

        let mut iter = set.iter();

        assert_eq!(iter.next(), Some(&1));
        assert_eq!(iter.next(), Some(&2));
        assert_eq!(iter.next(), Some(&3));
    }

    #[test]
    fn test_cmp_capacity() {
        assert!(Capacity::Unbounded > Capacity::bounded(NonZeroUsize::new(1000).unwrap()));
        assert!(
            Capacity::bounded(NonZeroUsize::new(1).unwrap())
                < Capacity::bounded(NonZeroUsize::new(1000).unwrap())
        );
        assert_eq!(Capacity::Unbounded, Capacity::Unbounded);
    }
}
