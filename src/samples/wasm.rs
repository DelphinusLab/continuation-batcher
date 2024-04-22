use core::panic;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

use delphinus_zkwasm::circuits::ZkWasmCircuit;
use delphinus_zkwasm::loader::ZkWasmLoader;

use delphinus_host::ExecutionArg as StandardArg;
use delphinus_host::HostEnvConfig;
use delphinus_zkwasm::runtime::host::HostEnvBuilder;
use delphinus_host::StandardHostEnvBuilder as StandardEnvBuilder;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::pairing::bn256::Fr;
use log::{error, info};
use specs::args::parse_args;

use crate::proof::ProofLoadInfo;
use crate::proof::ProofPieceInfo;

const IMAGE_CIRCUIT_SIZE: u32 = 18;
const AGGREGATE_CIRCUIT_SIZE: u32 = 22;

fn prove_wasm() {
    let wasm_binary = std::fs::read("path/to/wasm").unwrap();

    let private_input_str = vec![];
    let public_input_str = vec!["i64:3".to_string(), "i64:2".to_string()];
    let private_inputs = parse_args(private_input_str.iter().map(|s| s.as_str()).collect());
    let public_inputs = parse_args(public_input_str.iter().map(|s| s.as_str()).collect());

    let context_outputs = Arc::new(Mutex::new(vec![]));

    // This part may fail if the circuit size supplied is too small for the WASM file supplied
    // And thus we should handle the panic here
    // It is expected that the proof is successfull if this thread exits successfully with the required data
    //
    let context_inputs = vec![];

    
    let handle = std::thread::spawn(move || {
        let config = HostEnvConfig::default();
        //* TODO error handling
        let loader =
            ZkWasmLoader::<Bn256, StandardArg, StandardEnvBuilder>::new(IMAGE_CIRCUIT_SIZE as u32, wasm_binary, vec![]).expect("Failed to create loader");

        let result = loader.run(
            StandardArg {
                    public_inputs,
                    private_inputs,
                    context_inputs,
                    context_outputs: context_outputs.clone(),
                    indexed_witness: Rc::new(RefCell::new(HashMap::new())),
                    tree_db: None
                },
            config,
            false,
            true).expect("Failed to run loader");

        let (circuit, instances) = loader
            .circuit_with_witness(result)
            .expect("Failed to get circuit with witness");
        
        // TODO: Check if instances is > 12 length


        // Return generated circuit and instances
        return Ok((circuit, instances, context_outputs.lock().unwrap().clone()))
    });

    let vkey_prefix = format!("image.{}", IMAGE_CIRCUIT_SIZE);
    const MAX_INSTANCE_SIZE: u32 = 12;
    let prover: ProofPieceInfo = ProofPieceInfo::new(vkey_prefix.clone(), 0, MAX_INSTANCE_SIZE);

    

    let circuit_gen: Result<(ZkWasmCircuit<Fr>, Vec<Fr>), _> = match handle.join() {
        // Thread exited successfully
        Ok(res) => {
            info!("circuit generation thread exited successfully");
            match res {
                Ok((circuit, instances, context_outputs)) => {

                    Ok((circuit, instances))
                },
                Err(e) => {
                    Err(e)
                }
            }
        }
        Err(e) => {
            let msg = if let Some(msg) = e.downcast_ref::<&'static str>() {
                format!("Panic running proof: {}. Please check the logfile on the prover node for details.", msg.to_string())
            } else if let Some(msg) = e.downcast_ref::<String>() {
                format!("Panic running proof: {}. Please check the logfile on the prover node for details.", msg.clone())
            } else {
                format!("Panic running proof: {:?}. Please check the logfile on the prover node for details.", e)
            };

            panic!("{}", msg);
        }
    };

    let (circuit, instances) = match circuit_gen {
        Ok((circuit, instances)) => (circuit, instances),
        Err(e) => {
            panic!("Failed to generate circuit: {:?}", e);
        }
    };

    // TODO: ProofLoadInfo
    let mut proof_load_info = ProofLoadInfo::new(
        &vkey_prefix, 
        IMAGE_CIRCUIT_SIZE as usize,
        crate::args::HashType::Poseidon);
    // circuit.proofloadinfo.save(&outputpath);
    // This generates everything we need in the folder
    info!("Creating single proof");
    let params_key = StaticFile::KParams { circuit_size }.as_cache_key();
    let params = unsafe {STATIC_PARAMS_CACHE.cache.get(&params_key).unwrap()};

    let pkey = load_or_build_pkey::<Bn256, ZkWasmCircuit<Fr>>(
        &params,
        &circuit,
        &StaticFile::CircuitData { circuit_size: circuit_size }.file_path(),
        &StaticFile::VKey { circuit_size: circuit_size }.file_path(),
        unsafe {&mut STATIC_PKEY_CACHE} 
        );

    let timer_indent_2 = NUM_INDENT.load(Ordering::Relaxed);
    let handle = std::thread::spawn(move || {

        // TODO: both can use
        // let proof = prover.exec_create_proof(
        //     &circuit, 
        //     &vec![instances.clone()], 
        //     &outputpath, 
        //     &param_dir, 
        //     StaticFile::KParams { circuit_size: circuit_size }.file_name(),
        //     circuit_size as usize, 
        //     unsafe {&mut STATIC_PKEY_CACHE},
        //     unsafe {&mut STATIC_PARAMS_CACHE},
        //     circuits_batcher::args::HashType::Poseidon
        // );

        // Pad the instances to Max instance size of 0s if less than 12

        let mut instances = instances.clone();
        while instances.len() < MAX_INSTANCE_SIZE as usize {
            instances.push(Fr::zero());
        }

        prover.exec_create_proof_with_params::<Bn256, _>(
            &circuit, 
            &vec![instances], 
            params,
            pkey,
            &outputpath,
            circuits_batcher::args::HashType::Poseidon
        );

        proof_load_info.append_single_proof(prover);
        proof_load_info.save(&outputpath);
}