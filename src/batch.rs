use crate::args::HashType;
use crate::args::OpenSchema;
use crate::proof::load_or_build_pkey;
use crate::proof::ParamsCache;
use crate::proof::ProofGenerationInfo;
use crate::proof::ProofInfo;
use crate::proof::ProofPieceInfo;
use crate::proof::ProvingKeyCache;
use ark_std::end_timer;
use ark_std::start_timer;
use halo2_proofs::arithmetic::Engine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuit_verifier::build_aggregate_verify_circuit;
use halo2aggregator_s::circuit_verifier::G2AffineBaseHelper;
use halo2aggregator_s::circuits::utils::{AggregatorConfig, TranscriptHash};
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
    pub is_final: bool,
}

impl<E: MultiMillerLoop + G2AffineBaseHelper> BatchInfo<E>
where
    NativeScalarEccContext<<E as Engine>::G1Affine>:
        PairingChipOps<<E as Engine>::G1Affine, <E as Engine>::Scalar>,
{
    pub fn get_agg_instance_size(&self) -> usize {
        if self.is_final {
            1
        } else {
            self.expose.len() * 3 + 1 + self.proofs.len() * 3
        }
    }
    fn get_commitment_index(
        &self,
        proofsinfo: &Vec<ProofGenerationInfo>,
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
        proofsinfo: &Vec<ProofGenerationInfo>,
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
        // each commitment as instances are grouped by 3
        // (proof index, _, first instance of commitment
        [idx, 0, ci.group_idx * 3 + 1]
    }

    pub fn load_commitments_check(
        &mut self,
        proofsinfo: &Vec<ProofGenerationInfo>,
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

    pub fn batch_proof(
        &self,
        proof_piece: ProofPieceInfo,
        param_folder: &PathBuf,
        cache_folder: &PathBuf,
        params_cache: &mut ParamsCache<E>,
        pkey_cache: &mut ProvingKeyCache<E>,
        use_select_chip: bool,
        hashtype: HashType,
        last_agg_info: Option<Vec<(usize, usize, E::Scalar)>>, // (proof_index, instance_col, hash)
        open_schema: OpenSchema,
    ) -> (
        ProofPieceInfo,
        Vec<<E as Engine>::Scalar>,
        Vec<<E as Engine>::Scalar>,
        <E as Engine>::Scalar,
    ) {
        let mut all_proofs = vec![];
        let mut vkeys = vec![];
        let mut instances = vec![];

        for proofinfo in self.proofs.iter() {
            instances.push(&proofinfo.instances);
        }

        for proofinfo in self.proofs.iter() {
            all_proofs.push(proofinfo.transcripts.clone());
        }

        let mut target_proof_max_instance = instances
            .iter()
            .map(|x| x.iter().map(|x| x.len()).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        let max_target_instances = *target_proof_max_instance
            .iter()
            .flatten()
            .max_by(|x, y| x.cmp(y))
            .unwrap();

        last_agg_info.clone().map(|x| {
            target_proof_max_instance[x[0].0] = vec![1];
        });

        for proofinfo in self.proofs.iter() {
            vkeys.push(&proofinfo.vkey);
        }

        println!("preparing batch circuit (is final {}):", self.is_final);
        for vkey in vkeys.iter() {
            println!("vkey named advices: {:?}", vkey.cs.named_advices);
        }
        println!("commitment equiv: {:?}", self.equivalents);
        println!("commitment expose: {:?}", self.expose);
        println!("commitment absorb: {:?}", self.absorb);
        println!(
            "target proof instance size: {:?}",
            target_proof_max_instance
        );
        println!("hash agg info: {:?}", last_agg_info);
        println!("target proof max instance: {:?}", target_proof_max_instance);

        let target_aggregator_constant_hash_instance_offset =
            last_agg_info.clone().map_or_else(|| vec![], |x| x.clone());

        let config = &AggregatorConfig {
            hash: TranscriptHash::Poseidon,
            commitment_check: self.equivalents.clone(),
            expose: self.expose.clone(),
            absorb: self.absorb.clone(),
            target_aggregator_constant_hash_instance_offset,
            target_proof_with_shplonk: vec![],
            target_proof_with_shplonk_as_default: (open_schema == OpenSchema::Shplonk),
            target_proof_max_instance,
            is_final_aggregator: self.is_final,
            prev_aggregator_skip_instance: vec![(1, 1)], // hash get absorbed automatically
            absorb_instance: last_agg_info.map_or_else(|| vec![], |x| vec![(0, 0, x[0].0, 1)]),
            use_select_chip,
        };

        let target_params = params_cache.generate_k_params(self.target_k).clone();
        let target_params_verifier: ParamsVerifier<E> =
            target_params.verifier(max_target_instances).unwrap();

        let params = params_cache.generate_k_params(self.batch_k);
        //let params_verifier: ParamsVerifier<E> = params.verifier(max_target_instances).unwrap();

        // circuit multi check
        println!("building aggregate circuit:");
        println!("instances {:?}", instances);
        println!("param verifier size {:?}", self.get_agg_instance_size());
        println!("agg config is {:?}", config.absorb_instance);
        let timer = start_timer!(|| "build aggregate verify circuit");
        let (circuit, instances, shadow_instance, hash) = build_aggregate_verify_circuit::<E>(
            &target_params_verifier,
            &vkeys,
            instances,
            all_proofs,
            config,
        );

        let agg_circuit = circuit.circuit_with_select_chip.unwrap();
        let pkey = load_or_build_pkey::<E, _>(
            &params,
            &agg_circuit,
            &param_folder.join(proof_piece.circuit.clone()),
            &param_folder.join(format!("{}.vkey.data", proof_piece.circuit.clone())),
            pkey_cache,
        );

        proof_piece.exec_create_proof_with_params::<E, _>(
            &agg_circuit,
            &vec![instances.clone()],
            params,
            pkey,
            cache_folder,
            hashtype,
            open_schema,
        );

        end_timer!(timer);
        (proof_piece, instances, shadow_instance, hash)
    }
}
