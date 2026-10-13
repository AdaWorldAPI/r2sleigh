//! The golden tests: radare2's r2r format, run against the shell this build produced.
//!
//! Each file under `tests/db/` holds tests as r2r writes them (tests/db/README.md). A test runs
//! `r2s -q -c CMDS ARGS FILE`; its stdout must be `EXPECT`, and its stderr `EXPECT_ERR` where one
//! is stated. `R2S_BLESS=1` writes what ran into the files, and a bless is a judged diff.

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use libtest_mimic::{Arguments, Failed, Trial};

/// One test as its file states it, and where its expectations sit there.
#[derive(Debug, Clone)]
struct Golden {
    file: PathBuf,
    name: String,
    binary: String,
    args: Vec<String>,
    commands: String,
    expect: Option<Block>,
    expect_err: Option<Block>,
    broken: bool,
    /// The line `RUN` is on: an expectation the test lacks is written before it.
    run: usize,
}

/// A stated value and the lines of its file it spans.
#[derive(Debug, Clone)]
struct Block {
    text: String,
    lines: Range<usize>,
}

/// What one test printed, where it differed from its file.
struct Blessing {
    golden: Golden,
    stdout: String,
    stderr: String,
}

const KEYS: [&str; 7] = [
    "NAME",
    "FILE",
    "ARGS",
    "CMDS",
    "EXPECT",
    "EXPECT_ERR",
    "BROKEN",
];

fn main() {
    let args = Arguments::from_args();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = root.canonicalize().unwrap_or(root);
    let bless = std::env::var_os("R2S_BLESS").is_some();
    let blessed = Arc::new(Mutex::new(Vec::new()));
    let goldens = load(&root.join("tests/db")).unwrap_or_else(|error| panic!("{error}"));
    let trials = goldens
        .into_iter()
        .map(|golden| {
            let name = format!("{}::{}", golden.file.display(), golden.name);
            let broken = golden.broken;
            let (root, blessed) = (root.clone(), Arc::clone(&blessed));
            Trial::test(name, move || {
                check(&golden, &root, bless.then_some(&*blessed))
            })
            .with_ignored_flag(broken)
        })
        .collect();
    let conclusion = libtest_mimic::run(&args, trials);
    let blessed = std::mem::take(&mut *blessed.lock().expect("no trial panicked holding it"));
    write(&root.join("tests/db"), blessed);
    conclusion.exit();
}

/// Every test of every file under `db`, files in path order.
fn load(db: &Path) -> Result<Vec<Golden>, String> {
    let mut files = Vec::new();
    let mut pending = vec![db.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            let named = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if path.is_dir() {
                pending.push(path);
            } else if !named.starts_with('.') && !named.ends_with(".md") {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut goldens = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let relative = path.strip_prefix(db).unwrap_or(&path).to_path_buf();
        goldens.extend(parse(&relative, &text)?);
    }
    Ok(goldens)
}

/// The tests one file states, each ended by `RUN`.
fn parse(file: &Path, text: &str) -> Result<Vec<Golden>, String> {
    let lines = text.lines().collect::<Vec<_>>();
    let at_line = |at: usize| format!("{}:{}", file.display(), at + 1);
    let mut tests = Vec::new();
    let mut fields = BTreeMap::new();
    let mut at = 0;
    while at < lines.len() {
        let line = lines[at];
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            at += 1;
            continue;
        }
        if line.trim() == "RUN" {
            tests.push(
                golden(file, std::mem::take(&mut fields), at)
                    .map_err(|error| format!("{}: {error}", at_line(at)))?,
            );
            at += 1;
            continue;
        }
        let Some((key, value)) = line.split_once('=').filter(|(key, _)| KEYS.contains(key)) else {
            return Err(format!(
                "{}: not one of {KEYS:?}=value: {line}",
                at_line(at)
            ));
        };
        let start = at;
        let text = match value.strip_prefix("<<") {
            Some(tag) => {
                let mut body = String::new();
                loop {
                    at += 1;
                    match lines.get(at) {
                        Some(next) if *next == tag => break,
                        Some(next) => {
                            body.push_str(next);
                            body.push('\n');
                        }
                        None => {
                            return Err(format!("{}: `{tag}` never closes {key}", at_line(start)));
                        }
                    }
                }
                body
            }
            None => value.to_owned(),
        };
        at += 1;
        let block = Block {
            text,
            lines: start..at,
        };
        if fields.insert(key, block).is_some() {
            return Err(format!("{}: {key} twice in one test", at_line(start)));
        }
    }
    if !fields.is_empty() {
        return Err(format!("{}: a test with no RUN", file.display()));
    }
    let mut names = std::collections::BTreeSet::new();
    if let Some(twice) = tests
        .iter()
        .find(|test: &&Golden| !names.insert(test.name.clone()))
    {
        return Err(format!("{}: NAME={} twice", file.display(), twice.name));
    }
    Ok(tests)
}

fn golden(file: &Path, mut fields: BTreeMap<&str, Block>, run: usize) -> Result<Golden, String> {
    let mut take = |key| {
        fields
            .remove(key)
            .map(|block: Block| block.text.trim_end_matches('\n').to_owned())
    };
    let name = take("NAME").ok_or("a test with no NAME")?;
    let binary = take("FILE").ok_or("a test with no FILE")?;
    let commands = take("CMDS").ok_or("a test with no CMDS")?;
    let args = take("ARGS")
        .map(|args| args.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    let broken = take("BROKEN").is_some_and(|broken| broken == "1");
    Ok(Golden {
        file: file.to_path_buf(),
        name,
        binary,
        args,
        commands,
        expect: fields.remove("EXPECT"),
        expect_err: fields.remove("EXPECT_ERR"),
        broken,
        run,
    })
}

/// Run one test, and either hold it to its file or, blessing, record what it printed.
fn check(
    golden: &Golden,
    root: &Path,
    blessed: Option<&Mutex<Vec<Blessing>>>,
) -> Result<(), Failed> {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", &golden.commands])
        .args(&golden.args)
        .arg(root.join(&golden.binary))
        .env("NO_COLOR", "1")
        .output()
        .map_err(|error| format!("r2s did not start: {error}"))?;
    let (stdout, stderr) = (lines(&done.stdout), lines(&done.stderr));
    if done.status.code().is_none() {
        return Err(format!("r2s died: {}\n{stderr}", done.status).into());
    }
    let expected = |block: &Option<Block>| block.as_ref().map(|block| block.text.clone());
    let out_ok = expected(&golden.expect).unwrap_or_default() == stdout;
    let err_ok = expected(&golden.expect_err).is_none_or(|expect| expect == stderr);
    if out_ok && err_ok {
        return Ok(());
    }
    if let Some(blessed) = blessed {
        let blessing = Blessing {
            golden: golden.clone(),
            stdout,
            stderr,
        };
        blessed
            .lock()
            .expect("no trial panicked holding it")
            .push(blessing);
        return Ok(());
    }
    let mut report = String::new();
    if !out_ok {
        report += &diff(
            "EXPECT",
            &expected(&golden.expect).unwrap_or_default(),
            &stdout,
        );
    }
    if !err_ok {
        report += &diff(
            "EXPECT_ERR",
            &expected(&golden.expect_err).unwrap_or_default(),
            &stderr,
        );
    }
    Err(format!("{report}bless with R2S_BLESS=1 once the diff is judged right").into())
}

/// Output as a heredoc holds it: every line ended.
fn lines(bytes: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

fn diff(key: &str, expected: &str, actual: &str) -> String {
    let diff = similar::TextDiff::from_lines(expected, actual);
    format!(
        "{key} differs:\n{}",
        diff.unified_diff().header("expected", "actual")
    )
}

/// Write each blessed test's output into its file: a stated expectation replaced where it stood,
/// a missing one before `RUN`.
fn write(db: &Path, blessed: Vec<Blessing>) {
    let mut by_file = BTreeMap::<PathBuf, Vec<Blessing>>::new();
    for blessing in blessed {
        by_file
            .entry(blessing.golden.file.clone())
            .or_default()
            .push(blessing);
    }
    for (file, mut blessings) in by_file {
        let path = db.join(&file);
        let text = std::fs::read_to_string(&path).expect("a file the run read");
        let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
        // From the bottom up, so each test's line numbers still hold when it is written.
        blessings.sort_by_key(|blessing| std::cmp::Reverse(blessing.golden.run));
        for Blessing {
            golden,
            stdout,
            stderr,
        } in blessings
        {
            let mut edits = vec![(&golden.expect, "EXPECT", stdout)];
            if golden.expect_err.is_some() {
                edits.push((&golden.expect_err, "EXPECT_ERR", stderr));
            }
            let at = |block: &Option<Block>| {
                block
                    .as_ref()
                    .map_or(golden.run..golden.run, |block| block.lines.clone())
            };
            // The later edit first, so the earlier one's lines still hold.
            edits.sort_by_key(|(block, ..)| std::cmp::Reverse(at(block).start));
            for (block, key, text) in edits {
                lines.splice(at(block), heredoc(key, &text));
            }
        }
        let mut written = lines.join("\n");
        written.push('\n');
        std::fs::write(&path, written).expect("the file is writable");
        eprintln!("blessed {}", path.display());
    }
}

/// `KEY=<<EOF`, the text, `EOF`: a tag no line of the text is.
fn heredoc(key: &str, text: &str) -> Vec<String> {
    let mut tag = String::from("EOF");
    while text.lines().any(|line| line == tag) {
        tag.push('_');
    }
    std::iter::once(format!("{key}=<<{tag}"))
        .chain(text.lines().map(str::to_owned))
        .chain(std::iter::once(tag))
        .collect()
}
