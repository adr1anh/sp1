// TODO(adr1anh): Use LurkAir
// use sp1_core_machine::riscv::RiscvAir;
use sp1_stark::{CpuProver, MachineProver, StarkGenericConfig};

use crate::{CompressAir, CoreSC, InnerSC,
            ShrinkAir,
};

pub trait SP1ProverComponents: Send + Sync {
    // TODO(adr1anh): Use LurkAir
    /// The prover for making SP1 core proofs.
    type CoreProver: MachineProver<CoreSC, RiscvAir<<CoreSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;

    /// The prover for making SP1 recursive proofs.
    type CompressProver: MachineProver<InnerSC, CompressAir<<InnerSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;

    /// The prover for shrinking compressed proofs.
    type ShrinkProver: MachineProver<InnerSC, ShrinkAir<<InnerSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;
}

pub struct DefaultProverComponents;

impl SP1ProverComponents for DefaultProverComponents {
    // TODO(adr1anh): Use LurkAir
    type CoreProver = CpuProver<CoreSC, RiscvAir<<CoreSC as StarkGenericConfig>::Val>>;
    type CompressProver = CpuProver<InnerSC, CompressAir<<InnerSC as StarkGenericConfig>::Val>>;
    type ShrinkProver = CpuProver<InnerSC, ShrinkAir<<InnerSC as StarkGenericConfig>::Val>>;
}
