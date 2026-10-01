use binspect::render::{render, Show};
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(version, about = "Inspect ELF and PE executables")]
struct Cli {
    file: PathBuf,
    /// Section table (the default view, with segments for ELF)
    #[arg(short, long)]
    sections: bool,
    /// Program headers (ELF)
    #[arg(long)]
    segments: bool,
    /// Symbol tables
    #[arg(short = 'y', long)]
    symbols: bool,
    /// Imported functions
    #[arg(short, long)]
    imports: bool,
    /// Exported functions
    #[arg(short, long)]
    exports: bool,
    /// Relocations
    #[arg(short, long)]
    relocs: bool,
    /// Everything above
    #[arg(short, long)]
    all: bool,
    /// Rows per table, 0 for all
    #[arg(short, long, default_value_t = 40)]
    limit: usize,
    /// Only names containing this text (symbols, imports, exports)
    #[arg(short, long)]
    filter: Option<String>,
    /// Print the whole model as JSON
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let data = match std::fs::read(&cli.file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("binspect: {}: {e}", cli.file.display());
            return ExitCode::from(2);
        }
    };
    let bin = match binspect::parse(&data) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("binspect: {}: {e}", cli.file.display());
            return ExitCode::from(1);
        }
    };
    if cli.json {
        match serde_json::to_string_pretty(&bin) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("binspect: {e}");
                return ExitCode::from(2);
            }
        }
        return ExitCode::SUCCESS;
    }
    let none = !(cli.sections || cli.segments || cli.symbols || cli.imports || cli.exports || cli.relocs || cli.all);
    let show = Show {
        sections: cli.sections || cli.all || none,
        segments: cli.segments || cli.all || none,
        symbols: cli.symbols || cli.all,
        imports: cli.imports || cli.all,
        exports: cli.exports || cli.all,
        relocations: cli.relocs || cli.all,
        limit: cli.limit,
        filter: cli.filter,
    };
    print!("{}", render(&bin, &cli.file.display().to_string(), &show));
    ExitCode::SUCCESS
}
