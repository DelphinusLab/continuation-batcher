use crate::proof::ProofInfo;
use crate::proof::ProofLoadInfo;
use ark_std::end_timer;
use ark_std::start_timer;
use halo2_proofs::arithmetic::Engine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2aggregator_s::circuit_verifier::build_aggregate_verify_circuit;
use halo2aggregator_s::circuit_verifier::circuit::AggregatorCircuit;
use halo2aggregator_s::circuit_verifier::G2AffineBaseHelper;
use halo2aggregator_s::circuits::utils::{
    load_or_build_vkey, load_or_create_proof, AggregatorConfig, TranscriptHash,
};
use halo2aggregator_s::native_verifier;
use halo2aggregator_s::NativeScalarEccContext;
use halo2aggregator_s::PairingChipOps;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitmentName {
    pub name: String,
    pub proof_idx: usize,
    pub column_name: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitmentInInstance {
    pub name: String,
    pub proof_idx: usize,
    pub group_idx: usize, // instances are grouped by 3 as commits
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitmentEquivPair {
    pub source: CommitmentName,
    pub target: CommitmentName,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitmentAbsorb {
    pub instance_idx: CommitmentInInstance,
    pub target: CommitmentName,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitmentCheck {
    pub equivalents: Vec<CommitmentEquivPair>,
    pub expose: Vec<CommitmentName>,
    pub absorb: Vec<CommitmentAbsorb>,
}

pub struct LastAggInfo<E: MultiMillerLoop> {
    pub circuit: Option<AggregatorCircuit<E::G1Affine>>,
    pub instances: Option<Vec<E::Scalar>>,
    pub idx: usize,
}

impl CommitmentCheck {
    pub fn load(equiv_file: &Path) -> Self {
        let fd = std::fs::File::open(equiv_file)
            .expect("Can not find batch config for commitment arith. [--commits]");
        println!("read commit equivalents {:?}", equiv_file);
        serde_json::from_reader(fd).unwrap()
    }

    pub fn save(&self, equiv_file: &Path) {
        let fd = std::fs::File::create(equiv_file).unwrap();
        serde_json::to_writer_pretty(fd, self).unwrap()
    }
}

pub struct BatchInfo<E: MultiMillerLoop> {
    pub proofs: Vec<ProofInfo<E>>,
    pub batch_k: usize,
    pub target_k: usize,
    pub equivalents: Vec<[usize; 4]>,
    pub expose: Vec<[usize; 2]>,
    pub absorb: Vec<([usize; 3], [usize; 2])>,
}

impl<E: MultiMillerLoop + G2AffineBaseHelper> BatchInfo<E>
where
    NativeScalarEccContext<<E as Engine>::G1Affine>:
        PairingChipOps<<E as Engine>::G1Affine, <E as Engine>::Scalar>,
{
    fn get_commitment_index(
        &self,
        proofsinfo: &Vec<ProofLoadInfo>,
        cn: &CommitmentName,
    ) -> (usize, usize) {
        let mut idx = 0;
        let mut column_idx = None;
        for proofinfo in proofsinfo.iter() {
            if proofinfo.name == cn.name {
                idx += cn.proof_idx;
                let c = self.proofs[idx]
                    .vkey
                    .cs
                    .named_advices
                    .iter()
                    .position(|r| r.0 == cn.column_name)
                    .unwrap();
                column_idx = Some(self.proofs[idx].vkey.cs.named_advices[c].1);
                break;
            } else {
                idx += proofinfo.proofs.len()
            }
        }
        if column_idx.is_none() {
            println!("Can not locate commit name {:?}", cn);
            println!(
                "in {:?}",
                proofsinfo
                    .iter()
                    .map(|x| x.name.clone())
                    .collect::<Vec<_>>()
            );
        }
        (idx, column_idx.unwrap() as usize)
    }

    fn get_instance_index(
        &self,
        proofsinfo: &Vec<ProofLoadInfo>,
        ci: &CommitmentInInstance,
    ) -> [usize; 3] {
        let mut idx = 0;
        for proofinfo in proofsinfo.iter() {
            if proofinfo.name == ci.name {
                idx += ci.proof_idx;
                break;
            } else {
                idx += proofinfo.proofs.len()
            }
        }
        [idx, 0, ci.group_idx * 3] // each commitment as instances are grouped by 3
    }

    pub fn load_commitments_check(
        &mut self,
        proofsinfo: &Vec<ProofLoadInfo>,
        commits: CommitmentCheck,
    ) {
        for eqs in commits.equivalents.iter() {
            let src = self.get_commitment_index(proofsinfo, &eqs.source);
            let target = self.get_commitment_index(proofsinfo, &eqs.target);
            self.equivalents.push([src.0, src.1, target.0, target.1])
        }
        for exp in commits.expose.iter() {
            let s = self.get_commitment_index(proofsinfo, exp);
            self.expose.push([s.0, s.1]);
        }
        for absorb in commits.absorb.iter() {
            let s = self.get_instance_index(proofsinfo, &absorb.instance_idx);
            let t = self.get_commitment_index(proofsinfo, &absorb.target);
            self.absorb.push((s, [t.0, t.1]));
        }
    }

    pub fn build_aggregate_circuit(
        &self,
        proof_name: String,
        params: &Params<E::G1Affine>,
        param_folder: &PathBuf,
        cache_folder: &PathBuf,
        last_agg: Option<LastAggInfo<E>>,
        is_final: bool,
        target_aggregator_constant_hash_instance_offset: &Vec<(usize, usize, E::Scalar)>, // (proof_index, instance_col, hash)
    ) -> (
        AggregatorCircuit<<E as Engine>::G1Affine>,
        Vec<<E as Engine>::Scalar>,
        Vec<<E as Engine>::Scalar>,
        <E as Engine>::Scalar,
    ) {
        let mut all_proofs = vec![];
        let mut public_inputs_size = 0;
        let mut vkeys = vec![];
        let mut instances = vec![];

        let agg_vkey;
        let last_agg_instance_vec;

        if let Some(last_agg) = last_agg {
            // push proof
            let proof = &self.proofs[last_agg.idx];
            all_proofs.push((&proof.transcripts).clone());
            vkeys.push(&proof.vkey);
            instances.push(&proof.instances);

            // push agg when idx > 0
            let mut agg_idx = last_agg.idx;
            // need to generalize this
            public_inputs_size = 10;
            if agg_idx > 0 {
                // not the first circuit
                agg_idx -= 1;
                let agg_circuit = last_agg.circuit.unwrap();
                let last_agg_instance = last_agg.instances.unwrap();
                agg_vkey = load_or_build_vkey::<E, _>(
                    &params,
                    &agg_circuit,
                    Some(&param_folder.join(format!("{}.{}.vkey.data", proof_name, agg_idx))),
                );
                vkeys.push(&agg_vkey);

                let agg_proof = load_or_create_proof::<E, _>(
                    &params,
                    agg_vkey.clone(),
                    agg_circuit,
                    &[&last_agg_instance[..]][..],
                    Some(&cache_folder.join(format!("{}.{}.transcript.data", proof_name, agg_idx))),
                    TranscriptHash::Poseidon,
                    true,
                    true,
                );
                all_proofs.push(agg_proof);
                last_agg_instance_vec = vec![last_agg_instance];
                instances.push(&last_agg_instance_vec);
                public_inputs_size = 0;
            }
        } else {
            for (_, proof) in self.proofs.iter().enumerate() {
                all_proofs.push((&proof.transcripts).clone());
                vkeys.push(&proof.vkey);
                instances.push(&proof.instances);
            }
        }
        //public_inputs_size += proof.instances.len() * 3;
        public_inputs_size += instances.iter().fold(0usize, |acc, x| {
            usize::max(acc, x.iter().fold(0, |acc, x| usize::max(acc, x.len())))
        });

        let target_proof_max_instance = instances
            .iter()
            .map(|x| x.iter().map(|x| x.len()).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        println!("public input size {}", public_inputs_size);

        let params_verifier: ParamsVerifier<E> = params.verifier(public_inputs_size).unwrap();

        if false {
            println!("check single proof for each proof info:");
            let timer = start_timer!(|| "native verify single proof");
            for (_, proof) in self.proofs.iter().enumerate() {
                //println!("proof is {:?}", proof.transcripts);
                //println!("instance is {:?}", proof.instances);
                native_verifier::verify_single_proof::<E>(
                    &params_verifier,
                    &proof.vkey,
                    &proof.instances,
                    proof.transcripts.clone(),
                    TranscriptHash::Poseidon,
                    true,
                    &vec![],
                );
            }
            end_timer!(timer);
        }
        println!("done!");

        println!("preparing batch circuit:");
        for vkey in vkeys.iter() {
            println!("vkey named advices: {:?}", vkey.cs.named_advices);
        }
        println!("commitment equiv: {:?}", self.equivalents);
        println!("commitment expose: {:?}", self.expose);
        println!("commitment absorb: {:?}", self.absorb);

        let config = &AggregatorConfig {
            hash: TranscriptHash::Poseidon,
            commitment_check: self.equivalents.clone(),
            expose: self.expose.clone(),
            absorb: self.absorb.clone(),
            target_aggregator_constant_hash_instance_offset:
                target_aggregator_constant_hash_instance_offset.clone(), // hash instance of the proof index
            target_proof_with_shplonk: vec![],
            target_proof_with_shplonk_as_default: true,
            target_proof_max_instance,
            is_final_aggregator: is_final,
            //is_final_aggregator: true,
            prev_aggregator_skip_instance: vec![], // hash get absorbed automatically
            absorb_instance: vec![],
            use_select_chip: true,
        };

        // circuit multi check
        let timer = start_timer!(|| "build aggregate verify circuit");
        let (circuit, instances, shadow_instance, hash) = build_aggregate_verify_circuit::<E>(
            &params_verifier,
            &vkeys,
            instances,
            all_proofs,
            config,
        );

        end_timer!(timer);
        (
            circuit.circuit_with_select_chip.unwrap(),
            instances,
            shadow_instance,
            hash,
        )
    }
}
