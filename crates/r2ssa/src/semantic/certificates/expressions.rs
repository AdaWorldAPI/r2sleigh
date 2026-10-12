//! Which values a statement may spell, and which merge is a choice.

use super::super::*;

pub(crate) fn collect_renderable_expression_values(
    function: &SSAFunction,
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    structured: &StructuredDataflowFacts,
) -> crate::dense::IdSet<ValueId> {
    let certified_memory_read_insts = structured
        .memory_accesses
        .values()
        .filter(|access| !access.is_write && access.width > 0)
        .map(|access| access.id.inst)
        .collect::<crate::dense::IdSet<_>>();
    let mut renderable = crate::dense::IdSet::new(graph.values.len());
    let mut ready = VecDeque::new();

    for value in &graph.values {
        if expression_leaf_is_renderable(value) && renderable.insert(value.id) {
            ready.push_back(value.id);
        }
    }

    let mut eligible = vec![false; graph.insts.len()];
    let mut missing_inputs = vec![0usize; graph.insts.len()];
    for inst in &graph.insts {
        let Some(output) = inst.output else {
            continue;
        };
        if graph.value(output).is_none_or(|value| value.var.size == 0) {
            continue;
        }
        if !expression_inst_is_renderable(function, graph, inst, &certified_memory_read_insts) {
            continue;
        }

        if matches!(&inst.payload, InstPayload::Phi { .. }) {
            renderable.insert(output);
            ready.push_back(output);
        } else if matches!(
            &inst.payload,
            InstPayload::Op(
                SSAOp::Copy { .. }
                    | SSAOp::New { .. }
                    | SSAOp::Subpiece { .. }
                    | SSAOp::Piece { .. }
                    | SSAOp::IntZExt { .. }
                    | SSAOp::IntSExt { .. }
                    | SSAOp::Trunc { .. }
                    | SSAOp::Cast { .. }
            )
        ) {
            let input_renderable = graph
                .inputs(inst.id)
                .iter()
                .all(|i| renderable.contains(*i));
            if input_renderable {
                renderable.insert(output);
                ready.push_back(output);
            } else {
                eligible[inst.id.0 as usize] = true;
                missing_inputs[inst.id.0 as usize] = graph
                    .inputs(inst.id)
                    .iter()
                    .filter(|input| !renderable.contains(**input))
                    .count();
            }
        } else {
            eligible[inst.id.0 as usize] = true;
            missing_inputs[inst.id.0 as usize] = graph
                .inputs(inst.id)
                .iter()
                .filter(|input| !renderable.contains(**input))
                .count();
            if missing_inputs[inst.id.0 as usize] == 0 && renderable.insert(output) {
                ready.push_back(output);
            }
        }
    }

    // A loop phi is renderable once what enters it is and its back edge is
    // modulo itself, which reads the back edge's whole expression; so the
    // loop phis are tested again after each propagation. A round either adds
    // one or ends this, so there are at most one more round than loop phis,
    // and a round tests only those.
    let mut loop_phis = graph
        .insts
        .iter()
        .filter(|inst| matches!(inst.payload, InstPayload::Phi { .. }))
        .filter(|inst| {
            graph.block(inst.block).is_some_and(|block| {
                structured
                    .loops
                    .values()
                    .any(|fact| fact.header == block.addr)
            })
        })
        .collect::<Vec<_>>();
    let reads_memory = values_reading_memory(graph, !loop_phis.is_empty());
    let env = ExpressionRenderEnv {
        prep,
        graph,
        certified_memory_read_insts: &certified_memory_read_insts,
        reads_memory: &reads_memory,
    };
    loop {
        while let Some(value) = ready.pop_front() {
            for use_site in graph.use_sites(value) {
                let inst_idx = use_site.inst.0 as usize;
                if !eligible.get(inst_idx).copied().unwrap_or(false)
                    || missing_inputs.get(inst_idx).copied().unwrap_or(0) == 0
                {
                    continue;
                }
                missing_inputs[inst_idx] -= 1;
                if missing_inputs[inst_idx] == 0
                    && let Some(output) = graph.inst(use_site.inst).and_then(|inst| inst.output)
                    && renderable.insert(output)
                {
                    ready.push_back(output);
                }
            }
        }

        let mut added_loop_phi = false;
        loop_phis.retain(|inst| {
            inst.output
                .is_some_and(|output| !renderable.contains(output))
        });
        for inst in &loop_phis {
            let Some(output) = inst.output else {
                continue;
            };
            if renderable.contains(output) {
                continue;
            }
            if expression_loop_phi_is_renderable(&env, structured, inst, &renderable)
                && renderable.insert(output)
            {
                ready.push_back(output);
                added_loop_phi = true;
            }
        }
        if !added_loop_phi {
            break;
        }
    }

    renderable
}

pub(crate) fn expression_leaf_is_renderable(value: &crate::graph::GraphValue) -> bool {
    value.var.size > 0
        && (value.var.constant_bits().is_some()
            || (value.var.version == 0
                && matches!(
                    value.canonical_storage,
                    Some(CanonicalStorageId {
                        space: CanonicalStorageSpace::Register,
                        ..
                    })
                )))
}

pub(crate) fn expression_inst_is_renderable(
    _function: &SSAFunction,
    _graph: &SsaGraph,
    inst: &crate::graph::GraphInst,
    certified_memory_read_insts: &crate::dense::IdSet<InstId>,
) -> bool {
    match &inst.payload {
        InstPayload::Phi { .. } => true,
        InstPayload::Op(op) => {
            expression_op_is_pure(op)
                || (op.is_memory_read() && certified_memory_read_insts.contains(inst.id))
        }
    }
}

fn expression_phi_is_identity_renderable(
    env: &ExpressionRenderEnv<'_>,
    inst: &crate::graph::GraphInst,
) -> bool {
    let Some(first) = env.graph.inputs(inst.id).first() else {
        return false;
    };
    expression_phi_is_identity(env.graph, inst) && !env.reads_memory.contains(*first)
}

fn expression_phi_is_renderable(
    env: &ExpressionRenderEnv<'_>,
    inst: &crate::graph::GraphInst,
) -> bool {
    expression_phi_is_identity_renderable(env, inst)
        || expression_phi_has_single_canonical_root(env, inst)
}

fn expression_phi_has_single_canonical_root(
    env: &ExpressionRenderEnv<'_>,
    inst: &crate::graph::GraphInst,
) -> bool {
    let graph = env.graph;
    let Some(prep_facts) = env.prep else {
        return false;
    };
    // The inputs are one value when they name one representative: the same
    // bits at the same width, as the view states them. A representative the
    // graph holds no value for -- the literal a constant lane determines --
    // is compared as the variable it is.
    let mut roots = graph
        .inputs(inst.id)
        .iter()
        .filter(|input| graph.value(**input).is_some())
        .map(|input| {
            (
                crate::view::class_key(graph, &prep_facts.views, *input),
                *input,
            )
        });
    let Some((first_root, first_input)) = roots.next() else {
        return false;
    };
    let first = crate::view::class_value(graph, Some(&prep_facts.views), first_input);
    if env.reads_memory.contains(first) {
        return false;
    }
    roots.all(|(root, _)| root == first_root)
}

/// Every value computed, through any chain of definitions, from a memory read, where `asked`: one
/// pass from the reads along their uses, `O(V + E)`, where asking per value was a walk each.
fn values_reading_memory(graph: &SsaGraph, asked: bool) -> crate::dense::IdSet<ValueId> {
    let mut reads = crate::dense::IdSet::default();
    if !asked {
        return reads;
    }
    let mut work = (graph.insts.iter())
        .filter(|inst| matches!(&inst.payload, InstPayload::Op(op) if op.is_memory_read()))
        .filter_map(|inst| inst.output)
        .filter(|value| reads.insert(*value))
        .collect::<Vec<_>>();
    while let Some(value) = work.pop() {
        for site in graph.use_sites(value) {
            let output = graph.inst(site.inst).and_then(|inst| inst.output);
            work.extend(output.filter(|output| reads.insert(*output)));
        }
    }
    reads
}

fn expression_loop_phi_is_renderable(
    env: &ExpressionRenderEnv<'_>,
    structured: &StructuredDataflowFacts,
    inst: &crate::graph::GraphInst,
    renderable: &crate::dense::IdSet<ValueId>,
) -> bool {
    let graph = env.graph;
    let InstPayload::Phi { predecessors } = &inst.payload else {
        return false;
    };
    let Some(output) = inst.output else {
        return false;
    };
    let Some(header) = graph.block(inst.block).map(|block| block.addr) else {
        return false;
    };
    let Some(loop_fact) = structured.loops.values().find(|fact| fact.header == header) else {
        return false;
    };
    if graph.inputs(inst.id).len() != predecessors.len() {
        return false;
    }

    let latches = loop_fact.latches.iter().copied().collect::<BTreeSet<_>>();
    let mut saw_entry = false;
    let mut saw_backedge = false;
    for (pred_id, input) in predecessors
        .iter()
        .zip(graph.inputs(inst.id).iter().copied())
    {
        let Some(pred_addr) = graph.block(*pred_id).map(|block| block.addr) else {
            return false;
        };
        if latches.contains(&pred_addr) {
            saw_backedge = true;
            if !value_renderable_modulo_loop_phi(env, input, output, renderable) {
                return false;
            }
        } else {
            saw_entry = true;
            if !renderable.contains(input) {
                return false;
            }
        }
    }

    saw_entry && saw_backedge
}

pub(crate) struct ExpressionRenderEnv<'a> {
    pub(crate) prep: Option<&'a crate::DecompilePrepFacts>,
    pub(crate) graph: &'a SsaGraph,
    pub(crate) certified_memory_read_insts: &'a crate::dense::IdSet<InstId>,
    /// The values a memory read reaches (`values_reading_memory`).
    pub(crate) reads_memory: &'a crate::dense::IdSet<ValueId>,
}

/// Whether `value` is an expression over renderable values and `loop_phi`: each value decided once,
/// `O(V + E)`; one met while its inputs are open is on a cycle no expression spells.
pub(crate) fn value_renderable_modulo_loop_phi(
    env: &ExpressionRenderEnv<'_>,
    value: ValueId,
    loop_phi: ValueId,
    renderable: &crate::dense::IdSet<ValueId>,
) -> bool {
    let mut decided = crate::dense::IdMap::<ValueId, bool>::default();
    let mut open = crate::dense::IdSet::<ValueId>::default();
    let mut stack = vec![(value, false)];
    while let Some((at, inputs_done)) = stack.pop() {
        if at == loop_phi || renderable.contains(at) {
            decided.insert(at, true);
            continue;
        }
        let inst = env.graph.def_inst(at).and_then(|id| env.graph.inst(id));
        if inputs_done {
            let inputs = inst.map_or(&[][..], |inst| env.graph.inputs(inst.id));
            let all = inputs
                .iter()
                .all(|input| decided.get(*input).copied().unwrap_or(false));
            decided.insert(at, all);
            open.remove(at);
            continue;
        }
        if decided.contains(at) || !open.insert(at) {
            continue;
        }
        let Some(inst) = inst.filter(|inst| expression_eligible(env, inst)) else {
            decided.insert(at, false);
            open.remove(at);
            continue;
        };
        stack.push((at, true));
        stack.extend(
            env.graph
                .inputs(inst.id)
                .iter()
                .map(|input| (*input, false)),
        );
    }
    decided.get(value).copied().unwrap_or(false)
}

/// Whether one definition may stand inside a rendered expression.
fn expression_eligible(env: &ExpressionRenderEnv<'_>, inst: &crate::graph::GraphInst) -> bool {
    match &inst.payload {
        InstPayload::Phi { .. } => expression_phi_is_renderable(env, inst),
        InstPayload::Op(op) => {
            expression_op_is_pure(op)
                || (op.is_memory_read() && env.certified_memory_read_insts.contains(inst.id))
        }
    }
}

pub(crate) fn expression_op_is_pure<V>(op: &SSAOp<V>) -> bool {
    matches!(
        op,
        SSAOp::Copy { .. }
            | SSAOp::IntAdd { .. }
            | SSAOp::IntSub { .. }
            | SSAOp::IntMult { .. }
            | SSAOp::IntDiv { .. }
            | SSAOp::IntSDiv { .. }
            | SSAOp::IntRem { .. }
            | SSAOp::IntSRem { .. }
            | SSAOp::IntNegate { .. }
            | SSAOp::IntCarry { .. }
            | SSAOp::IntSCarry { .. }
            | SSAOp::IntSBorrow { .. }
            | SSAOp::IntAnd { .. }
            | SSAOp::IntOr { .. }
            | SSAOp::IntXor { .. }
            | SSAOp::IntNot { .. }
            | SSAOp::IntLeft { .. }
            | SSAOp::IntRight { .. }
            | SSAOp::IntSRight { .. }
            | SSAOp::IntEqual { .. }
            | SSAOp::IntNotEqual { .. }
            | SSAOp::IntLess { .. }
            | SSAOp::IntSLess { .. }
            | SSAOp::IntLessEqual { .. }
            | SSAOp::IntSLessEqual { .. }
            | SSAOp::IntZExt { .. }
            | SSAOp::IntSExt { .. }
            | SSAOp::BoolNot { .. }
            | SSAOp::BoolAnd { .. }
            | SSAOp::BoolOr { .. }
            | SSAOp::BoolXor { .. }
            | SSAOp::Piece { .. }
            | SSAOp::Subpiece { .. }
            | SSAOp::PopCount { .. }
            | SSAOp::Lzcount { .. }
            | SSAOp::FloatAdd { .. }
            | SSAOp::FloatSub { .. }
            | SSAOp::FloatMult { .. }
            | SSAOp::FloatDiv { .. }
            | SSAOp::FloatNeg { .. }
            | SSAOp::FloatAbs { .. }
            | SSAOp::FloatSqrt { .. }
            | SSAOp::FloatCeil { .. }
            | SSAOp::FloatFloor { .. }
            | SSAOp::FloatRound { .. }
            | SSAOp::FloatNaN { .. }
            | SSAOp::FloatEqual { .. }
            | SSAOp::FloatNotEqual { .. }
            | SSAOp::FloatLess { .. }
            | SSAOp::FloatLessEqual { .. }
            | SSAOp::Int2Float { .. }
            | SSAOp::Float2Int { .. }
            | SSAOp::FloatFloat { .. }
            | SSAOp::Trunc { .. }
            | SSAOp::PtrAdd { .. }
            | SSAOp::PtrSub { .. }
            | SSAOp::SegmentOp { .. }
            | SSAOp::Cast { .. }
            | SSAOp::Extract { .. }
            | SSAOp::Insert { .. }
            | SSAOp::Select { .. }
    )
}
