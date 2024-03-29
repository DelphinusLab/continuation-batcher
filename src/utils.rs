use sha2::Digest;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
pub fn construct_merkle_records(file: &PathBuf, data: &mut Vec<[u8; 32]>, depth: usize) {
    let len = data.len();
    let mut cursor = 0;
    let hasher = sha2::Sha256::new();
    for d in 0..depth {
        for _ in 0..2u32.pow((depth - d - 1) as u32) {
            let mut hasher = hasher.clone();
            hasher.update(data[cursor]);
            hasher.update(data[cursor + 1]);
            data.push(hasher.finalize().into());
            cursor += 2;
        }
    }

    assert!(data.len() == len * 2 - 1);
    let mut fd = std::fs::File::create(&file).unwrap();
    for v in data {
        fd.write(v.as_slice())
            .expect("writing merkle tree should not fail");
    }
}

pub fn construct_merkle_proof(file: &PathBuf, index: usize, depth: usize) -> Vec<[u8; 32]> {
    let mut data: Vec<[u8; 32]> = vec![];
    let mut fd = std::fs::File::open(&file).unwrap();
    for _ in 0..2 * 2u32.pow(depth as u32) - 1 {
        let mut d = [0; 32];
        fd.read(&mut d).expect("Read merkle data should not fail");
        data.push(d);
    }
    let hasher = sha2::Sha256::new();
    let mut acc = index;
    let mut comp = acc % 2;
    let mut base: usize = 0;
    let mut hash = data[acc];
    let mut proofs = vec![hash];
    for d in 0..depth {
        let mut hasher = hasher.clone();
        assert!(data[base + acc] == hash);
        if comp == 0 {
            hasher.update(data[base + acc]);
            hasher.update(data[base + acc + 1]);
            proofs.push(data[base + acc + 1]);
        } else {
            hasher.update(data[base + acc - 1]);
            hasher.update(data[base + acc]);
            proofs.push(data[base + acc - 1]);
        };
        hash = hasher.finalize().into();
        acc = acc / 2;
        comp = acc % 2;
        base = base + (2u32.pow((depth - d) as u32) as usize);
    }
    proofs
}

#[test]
fn merkle_test() {
    let mut hashes = vec![];
    for i in 0..1024u32 {
        hashes.push([(i % 256) as u8; 32]);
    }
    let filepath = PathBuf::from("test_merkle..data");
    construct_merkle_records(&filepath, &mut hashes, 10);
    let proofs = construct_merkle_proof(&filepath, 12, 10);
    println!("proofs is {:?}", proofs);
}
