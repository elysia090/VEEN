use std::env;

fn main() {
    let args: Vec<_> = env::args_os().collect();
    veen_cli::init_cli_binary_name(&args);

    let exit_code = match veen_cli::parse_cli(&args) {
        Ok(cli) => veen_cli::cli_main_from_parsed(cli),
        Err(err) => veen_cli::handle_parse_error(err, &args),
    };
    std::process::exit(exit_code);
}
