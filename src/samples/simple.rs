use ark_std::rand::rngs::OsRng;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::floor_planner::V1;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Advice;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Fixed;
use halo2_proofs::poly::Rotation;

#[derive(Clone)]
pub struct SimpleConfig {
    advices: [Column<Advice>; 2],
    sel: Column<Fixed>,
}

#[derive(Default, Clone)]
pub struct SimpleCircuit<F: FieldExt> {
    a: F,
    b: F,
}

impl<F: FieldExt> SimpleCircuit<F> {
    pub fn new_with_instance(a: F, b: F) -> Self {
        Self { a, b }
    }

    pub fn random_new_with_instance() -> (Self, Vec<Vec<F>>) {
        let a = F::random(OsRng);
        let b = F::random(OsRng);
        let instance = a + b;

        (Self::new_with_instance(a, b), vec![vec![instance]])
    }

    pub fn default_with_instance() -> (Self, Vec<Vec<F>>) {
        let a = F::zero();
        let b = F::zero();
        let instance = a + b;

        (Self::new_with_instance(a, b), vec![vec![instance]])
    }
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
        let advices = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let sel = meta.fixed_column();

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

        meta.enable_equality(advices[0]);
        meta.enable_equality(advices[1]);

        SimpleConfig { advices, sel }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "main",
            |mut region| {
                region.assign_advice(|| "a", config.advices[0], 0, || Ok(self.a))?;
                region.assign_advice(|| "b", config.advices[1], 0, || Ok(self.b))?;
                region.assign_fixed(|| "sel", config.sel, 0, || Ok(F::one()))?;
                region.assign_fixed(|| "sel", config.sel, 1, || Ok(F::zero()))?;

                if self.a != self.b {
                    region.assign_advice(|| "a", config.advices[0], 1, || Ok(self.b))?;
                    region.assign_advice(|| "b", config.advices[1], 1, || Ok(self.a))?;
                }

                Ok(())
            },
        )?;
        Ok(())
    }
}

#[test]
fn test_simple_diff() {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pairing::bn256::Fr;

    const K: u32 = 8;
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

    const K: u32 = 8;
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

    const K: u32 = 8;
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
