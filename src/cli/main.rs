use appbuilder::AppBuilder;
use halo2_proofs::pairing::bn256::Bn256;

pub mod appbuilder;
pub mod multi_proofs;
pub mod request;

mod test;

struct CircuitBatcherApp;

impl AppBuilder for CircuitBatcherApp {
    const NAME: &'static str = "auto-circuit-batcher";
    const VERSION: &'static str = "v0.1-beta";
    const MAX_PUBLIC_INPUT_SIZE: usize = 64;
}

/// Simple program to greet a person
fn main() -> anyhow::Result<()> {
    CircuitBatcherApp::exec::<Bn256>()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use assert_cmd::Command;

    #[test]
    fn test_setup() {
        let mut cmd = Command::cargo_bin("circuit-batcher").unwrap();

        cmd.arg("setup")
            .arg("-k")
            .arg("18")
            .arg("--params")
            .arg("./params")
            .assert()
            .success();
    }

    #[test]
    fn test_prove() {
        let mut cmd = Command::cargo_bin("circuit-batcher").unwrap();

        cmd.arg("prove")
            .arg("--proofs")
            .arg("./proofs")
            .assert()
            .success();
    }
}
