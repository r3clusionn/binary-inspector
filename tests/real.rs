//! Real files: ELF built by rustc and rust-lld (see tests/fixtures/tiny.rs for how), plus Windows
//! binaries that exist on every Windows machine. Expected values were cross-checked against
//! llvm-readobj when the tests were written.

use binspect::model::Format;
use binspect::parse;
use std::process::Command;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn object_file_interface_and_relocations() {
    let b = parse(&fixture("tiny.o")).unwrap();
    assert_eq!((b.format, b.kind.as_str(), b.bits), (Format::Elf, "relocatable object", 64));
    assert_eq!(b.sections.len(), 13);
    assert_eq!(b.imports.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["external_call"]);
    let mut exports: Vec<&str> = b.exports.iter().filter_map(|e| e.name.as_deref()).filter(|n| !n.starts_with("_R")).collect();
    exports.sort();
    assert_eq!(exports, ["add_one", "answer"]);
    assert_eq!(b.relocations.len(), 6);
    let call = b.relocations.iter().find(|r| r.symbol.as_deref() == Some("external_call")).unwrap();
    assert_eq!((call.offset, call.kind.as_str(), call.addend), (0x15, "R_X86_64_GOTPCREL", Some(-4)));
    // Relocations against section symbols are named after the section, as readelf does.
    assert!(b.relocations.iter().any(|r| r.symbol.as_deref() == Some(".text.answer")));
    assert!(b.features.is_empty(), "object files carry no hardening features: {:?}", b.features);
}

#[test]
fn shared_object_dynamic_information() {
    let b = parse(&fixture("libtiny.so")).unwrap();
    assert_eq!((b.kind.as_str(), b.soname.as_deref()), ("shared library", Some("libtiny.so")));
    assert_eq!(b.imports.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["external_call"]);
    assert_eq!(b.exports.iter().filter_map(|e| e.name.as_deref()).collect::<Vec<_>>(), ["add_one", "answer"]);
    assert_eq!(b.segments.iter().filter(|s| s.kind == "LOAD").count(), 4);
    assert!(b.features.contains(&"NX stack".to_string()));
    assert!(b.features.contains(&"full RELRO".to_string()));
    assert!(b.features.iter().all(|f| f != "PIE"), "a shared library is not a PIE executable");
    let add = b.exports.iter().find(|e| e.name.as_deref() == Some("add_one")).unwrap();
    let text = b.sections.iter().find(|s| s.name == ".text").unwrap();
    assert!(add.address >= text.address && add.address < text.address + text.size);
}

#[cfg(windows)]
#[test]
fn system_dll_exports_and_imports() {
    let path = r"C:\Windows\System32\kernel32.dll";
    let Ok(bytes) = std::fs::read(path) else { return };
    let b = parse(&bytes).unwrap();
    assert_eq!((b.format, b.kind.as_str()), (Format::Pe, "DLL"));
    assert!(b.exports.iter().any(|e| e.name.as_deref() == Some("CreateFileW")));
    assert!(b.exports.len() > 1000);
    assert!(b.imports.iter().any(|i| i.library.as_deref().is_some_and(|l| l.eq_ignore_ascii_case("ntdll.dll"))));
    assert!(b.features.contains(&"DEP".to_string()) && b.features.contains(&"ASLR".to_string()));
    assert!(b.sections.iter().any(|s| s.name == ".text" && s.permissions == "r-x"));
    assert!(b.notes.is_empty(), "{:?}", b.notes);
}

#[cfg(windows)]
#[test]
fn this_test_binary_is_a_pe_that_imports_kernel32() {
    let me = std::env::current_exe().unwrap();
    let b = parse(&std::fs::read(me).unwrap()).unwrap();
    assert_eq!(b.format, Format::Pe);
    assert!(b.libraries.iter().any(|l| l.eq_ignore_ascii_case("kernel32.dll")));
    assert!(b.imports.iter().any(|i| i.name == "CreateFileW" || i.name == "GetLastError"));
    assert!(b.sections.iter().any(|s| s.name == ".text"));
    assert!(b.relocations.len() > 10);
}

fn run(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_binspect")).args(args).output().unwrap();
    (o.status.code().unwrap(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

#[test]
fn cli_text_json_and_exit_codes() {
    let so = format!("{}/tests/fixtures/libtiny.so", env!("CARGO_MANIFEST_DIR"));
    let (code, out, _) = run(&[&so, "--all", "-l", "0"]);
    assert_eq!(code, 0);
    for want in ["ELF, 64-bit, x86-64, little endian", "shared library", "soname:     libtiny.so", "add_one", "external_call", "R_X86_64_", ".dynsym"] {
        assert!(out.contains(want), "missing {want:?} in\n{out}");
    }
    let (code, out, _) = run(&[&so, "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["format"], "Elf");
    assert_eq!(v["soname"], "libtiny.so");
    assert_eq!(v["exports"].as_array().unwrap().len(), 2);

    let (_, filtered, _) = run(&[&so, "-y", "-f", "ANSWER"]);
    assert!(filtered.contains("answer") && !filtered.contains("add_one"), "{filtered}");
    let (_, limited, _) = run(&[&so, "-y", "-l", "1"]);
    assert!(limited.contains("more (use --limit 0 for all)"), "{limited}");

    assert_eq!(run(&["no-such-file"]).0, 2);
    let manifest = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
    let (code, _, err) = run(&[&manifest]);
    assert_eq!(code, 1);
    assert!(err.contains("not an ELF or PE"), "{err}");
}
