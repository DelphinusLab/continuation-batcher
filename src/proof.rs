#[test]
fn batch_single_circuit() {
    //use crate::batch::BatchInfo;
    //use crate::proof::ProofInfo;
    use crate::proof::CircuitInfo;
    use crate::proof::Prover;
    use crate::samples::simple::SimpleCircuit;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::path::Path;

    env_logger::init();

    const K: u32 = 22;
    {
        let circuit = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let circuit_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit,
            "test1".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon,
        );

        circuit_info.mock_proof(K);
        let proofloadinfo = circuit_info.proofloadinfo.clone();
        circuit_info.create_witness(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );
        circuit_info.exec_create_proof(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );

        proofloadinfo.save(&Path::new("output"));
    }

    {
        let circuit = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let circuit_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit,
            "test2".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon,
        );

        circuit_info.mock_proof(K);
        let proofloadinfo = circuit_info.proofloadinfo.clone();
        circuit_info.create_witness(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );
        circuit_info.exec_create_proof(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );

        proofloadinfo.save(&Path::new("output"));
    }

    /*
    let batchinfo = BatchInfo::<Bn256> {
        proofs: ProofInfo::load_proof(&Path::new("output"), &proofloadinfo),
        target_k: K as usize,
        batch_k: BATCH_K as usize,
        commitment_check: vec![],
    };

    let agg_circuit = batchinfo.build_aggregate_circuit(&Path::new("output"), "aggregator".to_string(), HashType::Sha);
    agg_circuit.create_witness(&Path::new("output"), 0);
    agg_circuit.create_proof(&Path::new("output"), 0);
    */
}

#[test]
fn lru_drop() {
    // test should drop circuit "test2" after adding "test6".
    use crate::proof::CircuitInfo;
    use crate::proof::Prover;
    use crate::samples::simple::SimpleCircuit;
    use ark_std::end_timer;
    use ark_std::start_timer;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::path::Path;

    const K: u32 = 22;
    {
        let mut cproofloadinfo: Vec<ProofLoadInfo> = Vec::new();
        let mut cinfo: Vec<CircuitInfo<Bn256, SimpleCircuit<Fr>>> = Vec::new();
        for i in 1..=(DEFAULT_CACHE_SIZE + 1) {
            let circuit = || SimpleCircuit::<Fr> {
                a: Fr::from(100u64),
                b: Fr::from(200u64),
            };
            let testname = "test".to_owned() + &i.to_string();
            let circuitx_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
                circuit(),
                testname,
                vec![vec![Fr::from(300u64)]],
                K as usize,
                HashType::Poseidon,
            );
            circuitx_info.mock_proof(K);
            let proofloadinfox = circuitx_info.proofloadinfo.clone();
            cinfo.push(circuitx_info);
            cproofloadinfo.push(proofloadinfox);
        }

        for i in 0..=DEFAULT_CACHE_SIZE {
            let timer = start_timer!(|| "add circuit testx");
            cinfo.get(i).unwrap().create_witness(
                &Path::new("output"),
                &Path::new("params"),
                PKEY_CACHE.lock().as_mut().unwrap(),
                0,
                K_PARAMS_CACHE.lock().as_mut().unwrap(),
            );
            cproofloadinfo.get(i).unwrap().save(&Path::new("output"));
            end_timer!(timer);
        }

        let timer = start_timer!(|| "run circuit test1 again - should cache hit.");
        cinfo.get(0).unwrap().create_witness(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );
        cproofloadinfo.get(0).unwrap().save(&Path::new("output"));
        end_timer!(timer);

        let timer = start_timer!(|| "add circuit test6");
        cinfo.get(5).unwrap().create_witness(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );
        cproofloadinfo.get(5).unwrap().save(&Path::new("output"));
        end_timer!(timer);

        let key = "params/test2.circuit.data".to_string();
        if PKEY_CACHE.lock().as_mut().unwrap().contains(&key) {
            // CACHE HIT is a bad test result.
            assert!(false)
        } else {
            // CACHE MISS is agood test.
            assert!(true)
        }
    }
}
