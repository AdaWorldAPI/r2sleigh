//! A program's language is what its container states, wherever the language's own readers look.
//! The fixtures are written by `data/go_scanned.py`.

use r2image::SourceLanguage;

/// Build information found only by scanning `.data`, as Go's `debug/buildinfo` reads a stripped
/// PE, states Go: its version was read while the program was called C, so the Go ABI went unused.
#[test]
fn build_information_found_by_its_scan_states_go() {
    let bytes = include_bytes!("data/go_scanned.elf").to_vec();
    let image = r2image::Image::parse(bytes).expect("the scanned-Go fixture");
    let languages = &image.container().languages;
    assert_eq!(languages.go_version, Some((1, 21)));
    assert_eq!(languages.program, SourceLanguage::Go);
}

/// A development toolchain's version (`devel go1.24-...`) does not parse as a release, and the
/// build information still states Go: its header is the statement, its version a detail.
#[test]
fn build_information_states_go_whatever_its_version_says() {
    let bytes = include_bytes!("data/go_devel.elf").to_vec();
    let image = r2image::Image::parse(bytes).expect("the devel-Go fixture");
    let languages = &image.container().languages;
    assert_eq!(languages.go_version, None);
    assert_eq!(languages.program, SourceLanguage::Go);
}
