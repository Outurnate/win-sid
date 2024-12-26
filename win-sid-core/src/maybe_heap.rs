use std::hash::Hash;

#[derive(Debug, Eq, Clone)]
pub(super) enum MaybeHeap<const N: usize> {
    Stack([u32; N], usize),
    Heap(Box<[u32]>)
}

impl<const N: usize> MaybeHeap<N> {
    pub(super) fn as_slice(&self) -> &[u32] {
        match self {
            MaybeHeap::Stack(content, len) => &content[..(*len)],
            MaybeHeap::Heap(content) => content
        }
    }
}

impl<const N: usize> From<Vec<u32>> for MaybeHeap<N> {
    fn from(value: Vec<u32>) -> Self {
        Self::Heap(value.into_boxed_slice())
    }
}

impl<const N: usize> PartialEq for MaybeHeap<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> PartialOrd for MaybeHeap<N> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> Ord for MaybeHeap<N> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl<const N: usize> Hash for MaybeHeap<N> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}