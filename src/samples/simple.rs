use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::floor_planner::V1;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Fixed;
use halo2_proofs::plonk::{Advice, TableColumn};
use halo2_proofs::poly::Rotation;

#[derive(Clone)]
pub struct SimpleConfig {
    advices: [Column<Advice>; 3],
    sel: Column<Fixed>,
    table: TableColumn,
}

#[derive(Default, Clone)]
pub struct SimpleCircuit<F: FieldExt> {
    pub a: F,
    pub b: F,
}

impl<F: FieldExt> Circuit<F> for SimpleCircuit<F> {
    type Config = SimpleConfig;

    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            a: F::from(0),
            b: F::from(0),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advices = [
            meta.named_advice_column("A".to_string()),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let sel = meta.fixed_column();
        let table = meta.lookup_table_column();

        meta.create_gate("sum equals to instance", |meta| {
            let sel = meta.query_fixed(sel, Rotation(0));
            let a = meta.query_advice(advices[0], Rotation(0));
            let b = meta.query_advice(advices[1], Rotation(0));
            let instance = meta.query_instance(instance, Rotation(0));
            vec![sel * (a + b - instance)]
        });

        meta.lookup_any("a to b lookup", |meta| {
            let a = meta.query_advice(advices[0], Rotation(0));
            let b = meta.query_advice(advices[1], Rotation(0));
            vec![(a, b)]
        });

        meta.lookup_any("b to a lookup", |meta| {
            let a = meta.query_advice(advices[0], Rotation(0));
            let b = meta.query_advice(advices[1], Rotation(0));
            vec![(b, a)]
        });

        // construct lookup set
        meta.lookup("table0", |meta| {
            let input_0 = meta.query_advice(advices[0], Rotation::cur());
            [(input_0, table)].to_vec()
        });
        meta.lookup("table1", |meta| {
            let input_1 = meta.query_advice(advices[1], Rotation::cur());
            [(input_1 * F::from(2), table)].to_vec()
        });
        meta.lookup("table2", |meta| {
            let input_2 = meta.query_advice(advices[2], Rotation::cur());
            [(input_2, table)].to_vec()
        });

        meta.enable_equality(advices[0]);
        meta.enable_equality(advices[1]);

        SimpleConfig {
            advices,
            sel,
            table,
        }
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "main",
            |region| {
                region.assign_advice(|| "a", config.advices[0], 0, || Ok(self.a))?;
                region.assign_advice(|| "b", config.advices[1], 0, || Ok(self.b))?;
                region.assign_advice(|| "c", config.advices[2], 0, || Ok(self.a + self.b))?;
                region.assign_fixed(|| "sel", config.sel, 0, || Ok(F::one()))?;
                region.assign_fixed(|| "sel", config.sel, 1, || Ok(F::zero()))?;

                if self.a != self.b {
                    region.assign_advice(|| "a", config.advices[0], 1, || Ok(self.b))?;
                    region.assign_advice(|| "b", config.advices[1], 1, || Ok(self.a))?;
                }

                Ok(())
            },
        )?;

        layouter.assign_table(
            || "common range table",
            |t| {
                for i in 0..1024 {
                    t.assign_cell(|| "range tag", config.table, i, || Ok(F::from(i as u64)))?;
                }

                Ok(())
            },
        )
    }
}

#[test]
fn test_simple_diff() {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pairing::bn256::Fr;

    const K: u32 = 11;
    let circuit = SimpleCircuit::<Fr> {
        a: Fr::from(100u64),
        b: Fr::from(200u64),
    };
    let prover = match MockProver::run(K, &circuit, vec![vec![Fr::from(300u64)]]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_simple_same() {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pairing::bn256::Fr;

    const K: u32 = 11;
    let circuit = SimpleCircuit::<Fr> {
        a: Fr::from(10u64),
        b: Fr::from(10u64),
    };
    let prover = match MockProver::run(K, &circuit, vec![vec![Fr::from(20u64)]]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_simple_err() {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pairing::bn256::Fr;

    const K: u32 = 11;
    let circuit = SimpleCircuit::<Fr> {
        a: Fr::from(10u64),
        b: Fr::from(20u64),
    };
    let prover = match MockProver::run(K, &circuit, vec![vec![Fr::from(0u64)]]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert!(prover.verify().is_err());
}
