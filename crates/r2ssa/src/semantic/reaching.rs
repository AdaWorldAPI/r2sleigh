//! What one storage holds at the points a pass asks (adr-next-pass model 2).
//!
//! A block's entry is solved over the blocks backward-reachable from it through blocks that do
//! not write the storage: the whole-function walk's equations, closed over that region, so the
//! same least fixpoint, final once found and kept for the next ask.

use super::*;

/// A storage's state before an instruction, and at the start and end of its machine instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StorageBoundary {
    pub(crate) before: ReachingStorageState,
    pub(crate) instruction_start: ReachingStorageState,
    pub(crate) instruction_end: ReachingStorageState,
}

/// One storage's reaching states, solved where asked.
pub(crate) struct ReachingStorage<'a> {
    function: &'a SSAFunction,
    graph: &'a SsaGraph,
    storage: CanonicalStorageId,
    /// Each solved block's entry state.
    entries: BTreeMap<u64, ReachingStorageState>,
    /// Each block's last write to the storage, where it has one: what it hands its successors.
    kills: BTreeMap<u64, Option<ReachingStorageState>>,
    root_entry: Option<ReachingStorageState>,
    /// Every instruction of each block a query scanned.
    boundaries: crate::dense::IdMap<InstId, StorageBoundary>,
    scanned: BTreeSet<u64>,
}

impl<'a> ReachingStorage<'a> {
    pub(crate) fn new(
        function: &'a SSAFunction,
        graph: &'a SsaGraph,
        storage: CanonicalStorageId,
    ) -> Self {
        Self {
            function,
            graph,
            storage,
            entries: BTreeMap::new(),
            kills: BTreeMap::new(),
            root_entry: None,
            boundaries: crate::dense::IdMap::default(),
            scanned: BTreeSet::new(),
        }
    }

    /// The state before `inst`; none for an instruction no block operation is (a phi).
    pub(crate) fn before(&mut self, inst: InstId) -> Option<ReachingStorageState> {
        self.at(inst).map(|boundary| boundary.before)
    }

    /// The states around `inst`. O(its block) the first time its block is asked, O(1) after.
    pub(crate) fn at(&mut self, inst: InstId) -> Option<StorageBoundary> {
        if let Some(boundary) = self.boundaries.get(inst) {
            return Some(*boundary);
        }
        let block = self.graph.block_addr_of(inst)?;
        if self.scanned.insert(block) {
            self.scan(block);
        }
        self.boundaries.get(inst).copied()
    }

    fn scan(&mut self, block_addr: u64) {
        let mut state = self.entry(block_addr);
        let Some(block) = self.function.get_block(block_addr) else {
            return;
        };
        // The machine instruction being walked: its stamp, its start state and its insts.
        let mut pending: (Option<u64>, ReachingStorageState, Vec<InstId>) =
            (None, state, Vec::new());
        for (op, _) in block.sited() {
            let instruction = match self.function.arena().origin(op) {
                Some(crate::arena::OpOrigin::Lifted { instruction, .. }) => *instruction,
                _ => None,
            };
            if instruction.is_none() || instruction != pending.0 {
                for inst in pending.2.drain(..) {
                    self.close(inst, state);
                }
                pending.0 = instruction;
                pending.1 = state;
            }
            if let Some(inst) = self.graph.inst_for_op(op) {
                self.boundaries.insert(
                    inst,
                    StorageBoundary {
                        before: state,
                        instruction_start: pending.1,
                        instruction_end: state,
                    },
                );
                pending.2.push(inst);
            }
            state = written(self.graph, op, self.storage).unwrap_or(state);
        }
        for inst in pending.2 {
            self.close(inst, state);
        }
    }

    fn close(&mut self, inst: InstId, end: ReachingStorageState) {
        if let Some(boundary) = self.boundaries.get_mut(inst) {
            boundary.instruction_end = end;
        }
    }

    /// The state a block hands on where it writes the storage: its last write decides it.
    fn kill(&mut self, block_addr: u64) -> Option<ReachingStorageState> {
        if let Some(kill) = self.kills.get(&block_addr) {
            return *kill;
        }
        let kill = match self.function.get_block(block_addr) {
            None => Some(ReachingStorageState::Conflict),
            Some(block) => block
                .sited()
                .rev()
                .find_map(|(op, _)| written(self.graph, op, self.storage)),
        };
        self.kills.insert(block_addr, kill);
        kill
    }

    fn entry(&mut self, block_addr: u64) -> ReachingStorageState {
        if let Some(state) = self.entries.get(&block_addr) {
            return *state;
        }
        let root = self.function.root();
        // The region: each unsolved block whose entry this one needs, with its predecessors.
        let mut region = BTreeMap::<u64, Vec<u64>>::new();
        let mut stack = vec![block_addr];
        while let Some(block) = stack.pop() {
            if region.contains_key(&block) || self.entries.contains_key(&block) {
                continue;
            }
            let predecessors = match block == root {
                true => Vec::new(),
                false => self.function.predecessors(block),
            };
            for predecessor in &predecessors {
                if !self.entries.contains_key(predecessor) && self.kill(*predecessor).is_none() {
                    stack.push(*predecessor);
                }
            }
            region.insert(block, predecessors);
        }
        // A transparent block's entry is its exit, read by its successors in the region.
        let mut readers = BTreeMap::<u64, Vec<u64>>::new();
        for (block, predecessors) in &region {
            for predecessor in predecessors {
                if region.contains_key(predecessor) {
                    readers.entry(*predecessor).or_default().push(*block);
                }
            }
        }
        // The walk's worklist over the region: each entry rises from `Unknown` at most twice.
        let mut solving = region
            .keys()
            .map(|block| (*block, ReachingStorageState::Unknown))
            .collect::<BTreeMap<_, _>>();
        let mut pending = region.keys().copied().collect::<BTreeSet<_>>();
        while let Some(block) = pending.pop_first() {
            let state = self.join(block, &region[&block], &solving);
            if solving.insert(block, state) == Some(state) {
                continue;
            }
            if self.kill(block).is_none() {
                pending.extend(readers.get(&block).into_iter().flatten().copied());
            }
        }
        self.entries.extend(solving);
        self.entries[&block_addr]
    }

    /// A block's entry from its predecessors' exits, as the reaching walk joined them.
    fn join(
        &mut self,
        block_addr: u64,
        predecessors: &[u64],
        solving: &BTreeMap<u64, ReachingStorageState>,
    ) -> ReachingStorageState {
        if block_addr == self.function.root() {
            return *self
                .root_entry
                .get_or_insert_with(|| entry_storage_state(self.graph, self.storage));
        }
        if predecessors.is_empty() {
            return ReachingStorageState::Conflict;
        }
        let known = predecessors
            .iter()
            .map(|predecessor| self.exit(*predecessor, solving))
            .filter(|state| *state != ReachingStorageState::Unknown)
            .collect::<Vec<_>>();
        let Some(first) = known.first().copied() else {
            return ReachingStorageState::Unknown;
        };
        if known.contains(&ReachingStorageState::Conflict) {
            return ReachingStorageState::Conflict;
        }
        match storage_phi_value(self.function, self.graph, block_addr, self.storage) {
            Ok(Some(value)) => ReachingStorageState::Value(value),
            Err(()) => ReachingStorageState::Conflict,
            Ok(None) if known.iter().all(|state| *state == first) => first,
            Ok(None) => ReachingStorageState::Conflict,
        }
    }

    fn exit(
        &mut self,
        block_addr: u64,
        solving: &BTreeMap<u64, ReachingStorageState>,
    ) -> ReachingStorageState {
        if let Some(kill) = self.kill(block_addr) {
            return kill;
        }
        solving
            .get(&block_addr)
            .or_else(|| self.entries.get(&block_addr))
            .copied()
            .unwrap_or(ReachingStorageState::Unknown)
    }
}

/// The state an operation leaves the storage in, where it decides one: a write of the storage
/// is its value, a write of part of it or an operation the graph lost is a conflict.
fn written(
    graph: &SsaGraph,
    op: OpId,
    storage: CanonicalStorageId,
) -> Option<ReachingStorageState> {
    let Some(inst) = graph.inst_for_op(op).and_then(|inst| graph.inst(inst)) else {
        return Some(ReachingStorageState::Conflict);
    };
    let written = inst.canonical_storage?;
    if !register_storages_overlap(written, storage) {
        return None;
    }
    if written != storage {
        return Some(ReachingStorageState::Conflict);
    }
    Some(
        inst.output
            .map(ReachingStorageState::Value)
            .unwrap_or(ReachingStorageState::Conflict),
    )
}

fn entry_storage_state(graph: &SsaGraph, storage: CanonicalStorageId) -> ReachingStorageState {
    let candidates = graph
        .values
        .iter()
        .filter(|value| {
            graph.def_inst(value.id).is_none()
                && value.var.version == 0
                && value.var.size == storage.size
                && value.canonical_storage == Some(storage)
        })
        .map(|value| value.id)
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [value] => ReachingStorageState::Value(*value),
        [] => ReachingStorageState::PreservedEntry,
        _ => ReachingStorageState::Conflict,
    }
}

fn storage_phi_value(
    function: &SSAFunction,
    graph: &SsaGraph,
    block_addr: u64,
    storage: CanonicalStorageId,
) -> Result<Option<ValueId>, ()> {
    let block = function.get_block(block_addr).ok_or(())?;
    let values = block
        .phis()
        .iter()
        .filter(|phi| phi.canonical_storage == Some(storage))
        .filter_map(|phi| graph.value_of(phi.dst))
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(*value)),
        _ => Err(()),
    }
}
