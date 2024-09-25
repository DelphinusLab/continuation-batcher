pub mod round1;

use crate::args::HashType;
use crate::args::OpenSchema;
use crate::batch::BatchInfo;
use crate::proof::load_or_build_unsafe_params;
use crate::proof::ParamsCache;
use crate::proof::ProofGenerationInfo;
use crate::proof::ProofInfo;
use crate::proof::ProofPieceInfo;
use crate::proof::ProvingKeyCache;

use ff::PrimeField;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::bn256::G1Affine;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuits::utils::store_instance;
use halo2aggregator_s::solidity_verifier::codegen::solidity_aux_gen;
use std::path::Path;


/// This function batch processes multiple proofs using the provided parameters and caches. \
/// `params_cache` and `pkey_cache` are mutable references to parameter and proving key caches respectively,
/// allowing for efficient reuse of previously computed parameters and keys. \
/// `proofs` is a vector of input proofs to be processed in batches. \
/// `batch_instances` is a vector containing the instances for each proof in the batch. \
/// `target_circuit_vkey` is the verifying key for the target (input) circuit to be verified. \
/// `proof_name` is a string identifying the type of proof being processed. \
/// `target_circuit_size` and `batch_circuit_size` represent the sizes of the target (input) and batch circuits respectively. \
/// `use_select_chip` indicates whether to use the select chip, mostly depends on if final batch or to be batched further. \
/// `output_folder` and `param_dir` are paths for output and parameter directories respectively. \
/// Returns a tuple containing the resulting transcripts, batch instances, shadow instances, and the aux (if generating solidity from it). \
pub fn batch_proofs(
    params_cache: &mut ParamsCache<Bn256>,
    pkey_cache: &mut ProvingKeyCache<Bn256>,
    proofs: Vec<Vec<u8>>,
    batch_instances: Vec<Vec<Fr>>,
    target_circuit_vkey: VerifyingKey<G1Affine>,
    proof_name: String,
    target_circuit_size: usize,
    batch_circuit_size: usize,
    use_select_chip: bool,
    output_folder: &Path,
    param_dir: &Path,
) -> (Vec<u8>, Vec<Fr>, Vec<Fr>, Vec<u8>) {
    let hashtype = match use_select_chip {
        true => HashType::Poseidon,
        false => HashType::Keccak,
    };

    let proofs = proofs
        .into_iter()
        .zip(batch_instances)
        .map(|(p, ins)| ProofInfo::<Bn256> {
            k: target_circuit_size,
            vkey: target_circuit_vkey.clone(),
            instances: [ins].to_vec(),
            transcripts: p,
            hashtype: crate::args::HashType::Poseidon,
        })
        .collect::<Vec<_>>();

    let batchinfo = BatchInfo::<Bn256> {
        proofs,
        target_k: target_circuit_size,
        batch_k: batch_circuit_size,
        equivalents: vec![],
        absorb: vec![],
        expose: vec![],
        is_final: true,
    };

    let proof_piece = ProofPieceInfo::new(proof_name.clone(), 0, batchinfo.get_agg_instance_size() as u32);

    let (proof_piece, instances, transcripts, shadow_instances, _last_hash) = batchinfo.batch_proof(
        proof_piece,
        params_cache,
        pkey_cache,
        use_select_chip,
        hashtype,
        None,
        OpenSchema::Shplonk,
        vec![],
        /* Latest batch version need this absorb_instance.
        Fill absorb_instance to empty is because last_agg_info is None.
        For detail, check https://github.com/DelphinusLab/continuation-batcher/commit/efac37426049484914c39117f9264fa00784846f#diff-4e790ee0f227ac85f8ae733dad110ee70439acb6ce6b780e5edb6199e040b574L236
        last_agg_info can be None is because we fill instance to 12 in runner try_prove MAX_INSTANCE_SIZE.
        if in the future we do not auto fill the instance to 12, this part need change.
        */
    );

    // TODO: Check if these file saves are required
    proof_piece.save_proof_data(&vec![instances.clone()], &transcripts, output_folder);

    let mut proof_generation_info = ProofGenerationInfo::new(&proof_name.as_str(), batch_circuit_size, hashtype);

    proof_generation_info.append_single_proof(proof_piece);
    proof_generation_info.save(output_folder);

    store_instance(
        &vec![shadow_instances.clone()],
        &output_folder.join(format!("{}.{}.shadowinstance.data", &proof_generation_info.name.clone(), 0)),
    );

    let mut aux = vec![];

    if hashtype == HashType::Sha || hashtype == HashType::Keccak {
        let param_file = format!("K{}.params", batch_circuit_size as usize);

        let proof: Vec<ProofInfo<Bn256>> = ProofInfo::load_proof(&output_folder, &param_dir, &proof_generation_info);

        println!("generate aux data for proof: {:?}", proof_generation_info);

        // setup batch params
        let params = load_or_build_unsafe_params::<Bn256>(
            proof_generation_info.k as usize,
            &param_dir.join(param_file),
            params_cache,
        );

        // the final instance size is 1
        let params_verifier: ParamsVerifier<Bn256> = params.verifier(1).unwrap();

        // generate solidity aux data
        // it only makes sense if the transcript challenge is poseidon
        match hashtype {
            HashType::Sha => {
                solidity_aux_gen::<_, sha2::Sha256>(
                    &params_verifier,
                    &proof[0].vkey,
                    &proof[0].instances[0],
                    proof[0].transcripts.clone(),
                    &output_folder.join(format!("{}.{}.aux.data", &proof_generation_info.name.clone(), 0)),
                );

                aux = std::fs::read(output_folder.join(format!(
                    "{}.{}.aux.data",
                    &proof_generation_info.name.clone(),
                    0
                )))
                .unwrap();
            }
            HashType::Keccak => {
                solidity_aux_gen::<_, sha3::Keccak256>(
                    &params_verifier,
                    &proof[0].vkey,
                    &proof[0].instances[0],
                    proof[0].transcripts.clone(),
                    &output_folder.join(format!("{}.{}.aux.data", &proof_generation_info.name.clone(), 0)),
                );

                aux = std::fs::read(output_folder.join(format!(
                    "{}.{}.aux.data",
                    &proof_generation_info.name.clone(),
                    0
                )))
                .unwrap();
            }
            HashType::Poseidon => unreachable!(),
        }
    }

    (transcripts, instances, shadow_instances, aux)
}

pub fn vec_fr_to_vec_u8(data: &Vec<Fr>) -> Vec<u8> {
    let u8s = data.iter().map(|f| f.to_repr()).flatten().collect::<Vec<u8>>();
    u8s
}