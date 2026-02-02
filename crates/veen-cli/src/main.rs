use std::env;

fn main() {
    let args: Vec<_> = env::args_os().collect();
    let exit_code = veen_cli::cli_main(&args);
    std::process::exit(exit_code);
}
