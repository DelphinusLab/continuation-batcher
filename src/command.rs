use clap::App;
use clap::Command;

use super::args::ArgBuilder;

pub trait CommandBuilder: ArgBuilder {
    fn append_params_subcommand(app: App) -> App {
        let command = Command::new("params").arg(Self::zkwasm_k_arg().required(true));
        app.subcommand(command)
    }

    fn append_setup_subcommand(app: App) -> App {
        let command = Command::new("setup")
            .arg(Self::output_path_arg())
            .arg(Self::zkwasm_k_arg());
        app.subcommand(command)
    }

    fn append_batch_subcommand(app: App) -> App {
        let command = Command::new("batch")
            .arg(Self::zkwasm_k_arg())
            .arg(Self::hashtype())
            .arg(Self::openschema())
            .arg(Self::proof_name_arg())
            .arg(Self::commits_info_arg())
            .arg(Self::accumulator())
            .arg(Self::proof_load_info_arg())
            .arg(Self::cont_arg());
        app.subcommand(command)
    }

    fn append_round_1_batch_subcommand(app: App) -> App {
        let command = Command::new("round1")
            .arg(Self::zkwasm_k_arg())
            .arg(Self::target_k())
            .arg(Self::proof_name_arg());
        app.subcommand(command)
    }

    fn append_verify_subcommand(app: App) -> App {
        let command = Command::new("verify")
            .arg(Self::hashtype())
            .arg(Self::proof_load_info_arg());

        app.subcommand(command)
    }

    fn append_generate_solidity_verifier(app: App) -> App {
        let command = Command::new("solidity")
            .arg(Self::zkwasm_k_arg())
            .arg(Self::hashtype())
            .arg(Self::commits_info_arg())
            .arg(Self::sol_dir_arg())
            .arg(Self::proof_load_info_arg());
        app.subcommand(command)
    }
}
