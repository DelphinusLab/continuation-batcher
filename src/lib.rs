pub mod appbuilder;
pub mod args;
pub mod batch;
pub mod command;
pub mod exec;
pub mod proof;
pub mod samples;

#[test]
fn test_batch_rec_aggregator() {
    use crate::exec;
    use halo2aggregator_s::circuits::samples::simple::SimpleCircuit;
    use halo2aggregator_s::circuits::utils::run_circuit_unsafe_full_pass;
    use halo2aggregator_s::circuits::utils::run_circuit_with_agg_unsafe_full_pass;
    use halo2aggregator_s::circuits::utils::TranscriptHash;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::fs::DirBuilder;
    use std::path::Path;
    use crate::proof::Prover;
    use std::path::PathBuf;
    use crate::{proof::{K_PARAMS_CACHE, PKEY_CACHE, CircuitInfo}, batch::CommitmentCheck, args::HashType};

    let k = 22;
    //===========get hash from halo2_aggregator_s test=====================//
    let output_path = "./output/agg";
    DirBuilder::new().recursive(true).create(output_path).unwrap();

    let path = Path::new(output_path.clone());
    let (circuit, target_instances) = SimpleCircuit::<Fr>::default_with_instance();

    let circuit_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
        circuit.clone(),
        "simple-circuit".to_string(),
        target_instances.clone(),
        k as usize,
        HashType::Poseidon,
    );


    circuit_info.proofloadinfo.save(path.clone());

    circuit_info.create_witness(
        path.clone(),
        path.clone(),
        PKEY_CACHE.lock().as_mut().unwrap(),
        0,
        K_PARAMS_CACHE.lock().as_mut().unwrap(),
    );

    let (agg_l0, agg_l0_instances, hash) = run_circuit_unsafe_full_pass::<Bn256, _>(
        path,
        "simple-circuit",
        k,
        vec![circuit.clone()],
        vec![target_instances.clone()],
        TranscriptHash::Poseidon,
        vec![[0, 0, 0, 0]],
        vec![],
        vec![],
        false,
        &vec![],
    )
    .unwrap();
    println!(
        "build agg 0 done, hash is {:?}, instance is {:?}",
        hash, agg_l0_instances
    );

    let mut hashes = vec![hash];
    let mut final_hashes = vec![hash];

    let mut last_agg = agg_l0;
    let mut last_agg_instances = agg_l0_instances;
    for i in 1..5 {
        let (agg, instances, hash) = run_circuit_with_agg_unsafe_full_pass::<Bn256, _>(
            path,
            "simple-circuit",
            k,
            vec![circuit.clone()],
            vec![target_instances.clone()],
            last_agg,
            last_agg_instances,
            TranscriptHash::Poseidon,
            vec![[0, 0, 0, 0]],
            vec![],
            vec![],
            false,
            &vec![(1, 0, *final_hashes.last().unwrap())],
            i,
        )
        .unwrap();
        println!(
            "build agg {} done, hash is {:?}, instance is {:?}",
            i, hash, instances
        );
        hashes.push(hash);
        final_hashes.push(instances[0]);
        last_agg = agg;
        last_agg_instances = instances;
    }

    let last_hash = hashes.pop().unwrap();

    //===========get hash from continuation batcher =====================//
    let batch_output_path = "./output".to_string();
    let loadinfo = "/simple-circuit.loadinfo.json";
    let load_info_path = batch_output_path.clone() + loadinfo;

    std::fs::copy(output_path.to_string() + loadinfo, &load_info_path).unwrap();
    let circuit_data = "/simple-circuit.circuit.data";
    std::fs::copy(output_path.to_string() + circuit_data, batch_output_path.clone() + circuit_data).unwrap();
    let transcripts = "/simple-circuit.0.transcript.data";
    std::fs::copy(output_path.to_string() + transcripts, batch_output_path.clone() + transcripts).unwrap();
    let instances = "/simple-circuit.0.instance.data";
    std::fs::copy(output_path.to_string() + instances, batch_output_path.clone() + instances).unwrap();
    let params = &format!("/K{}.params", k);
    std::fs::copy(output_path.to_string() + params, batch_output_path.clone() + params).unwrap();

    let config_files = vec![PathBuf::from("./output/simple-circuit.loadinfo.json");5];
    let rec_last_hash = exec::exec_batch_proofs_cont(
        K_PARAMS_CACHE.lock().as_mut().unwrap(),
        &String::from("simple-circuit"),
        &PathBuf::from(&batch_output_path),
        &PathBuf::from(&batch_output_path),
        config_files,
        CommitmentCheck::load(Path::new("./sample/batchinfo.rec.json")),
        HashType::Poseidon,
        k
    );

    assert_eq!(last_hash, rec_last_hash);
}
