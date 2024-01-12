use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::arithmetic::MultiMillerLoop;
use std::{fs::File, io};

pub fn load_instances<E: MultiMillerLoop>(
    n_rows: &[u32],
    fd: &mut File,
) -> io::Result<Vec<Vec<E::Scalar>>> {
    let mut instances = vec![];

    for n_row in n_rows {
        let mut col = vec![];

        for _ in 0..*n_row {
            col.push(E::Scalar::read(fd)?);
        }

        instances.push(col);
    }

    Ok(instances)
}
