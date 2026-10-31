//! `afw` command-line interface (lot L8).

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let mut stdin = std::io::stdin();
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let io = afw_cli::Io {
        out: &mut out,
        err: &mut err,
        stdin: &mut stdin,
        env_token: env("AFW_TOKEN"),
        coolify_token: env("AFW_COOLIFY_TOKEN"),
        docker: env("AFW_DOCKER").unwrap_or_else(|| "docker".into()),
    };
    let code = afw_cli::run(std::env::args_os(), io).await;
    std::process::exit(code);
}
