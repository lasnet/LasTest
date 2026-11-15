use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    lastest::cli::run().await
}
