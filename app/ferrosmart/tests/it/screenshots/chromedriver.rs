// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The chromedriver a browser session runs through: one per session, on a
//! port the system picks, in a process group of its own that is killed with
//! the session, after FerroPIX's harness. A chromedriver that exits because
//! the port it picked is bound already is started again; any other exit
//! before it listens fails the session with what it wrote.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout, Command};

use crate::screenshots::{WAIT, workspace};

/// The environment variable naming the chromedriver binary, when it is not
/// the one in [`installed`], or else [`CHROMEDRIVER`] on `PATH`.
const CHROMEDRIVER_ENV: &str = "FERROSMART_CHROMEDRIVER";

/// The environment variable naming the Chrome binary, when it is not the one
/// in [`installed`], or else the one chromedriver finds itself.
pub(crate) const CHROME_ENV: &str = "FERROSMART_CHROME";

/// The chromedriver binary looked up on `PATH`.
const CHROMEDRIVER: &str = "chromedriver";

/// What chromedriver prints once it listens, before the port it chose.
const LISTENING: &str = "ChromeDriver was started successfully on port ";

/// What chromedriver logs when the port it picked is bound already.
const PORT_TAKEN: &str = "Address already in use";

/// How many times a chromedriver is started before a port bound already
/// fails the session.
const STARTS: u32 = 5;

/// Where `scripts/release/journey-tools.sh` unpacks chromedriver and Chrome
/// for this platform, under the workspace's `target/journey-tools`: the
/// Chrome for Testing platform name, and the Chrome binary inside its
/// directory.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const INSTALLED: Option<(&str, &str)> = Some(("linux64", "chrome"));
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const INSTALLED: Option<(&str, &str)> = Some((
    "mac-arm64",
    "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
));
#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
)))]
const INSTALLED: Option<(&str, &str)> = None;

/// The chromedriver and the Chrome binary `scripts/release/journey-tools.sh`
/// installed for this platform, each when it is there.
pub(crate) fn installed() -> (Option<PathBuf>, Option<PathBuf>) {
    let Some((platform, chrome)) = INSTALLED else {
        return (None, None);
    };
    let tools = workspace().join("target/journey-tools");
    let driver = tools.join(format!("chromedriver-{platform}/chromedriver"));
    let chrome = tools.join(format!("chrome-{platform}")).join(chrome);
    (
        driver.is_file().then_some(driver),
        chrome.is_file().then_some(chrome),
    )
}

/// A chromedriver one session runs through, in a process group of its own
/// that is killed when it is dropped, so the Chrome it launched goes with it
/// even when a journey panics.
#[derive(Debug)]
pub(crate) struct Chromedriver {
    /// The chromedriver process.
    child: Child,
    /// Its standard output, held open so a later line never meets a closed
    /// pipe.
    _stdout: Lines<BufReader<ChildStdout>>,
    /// The file its standard error goes to, read when it exits before it
    /// listens.
    _stderr: NamedTempFile,
}

/// How one start of a chromedriver ended.
#[derive(Debug)]
enum Start {
    /// It listens on the port.
    Listening(Box<Chromedriver>, u16),
    /// It exited because the port it picked was bound already, with what it
    /// wrote.
    PortTaken(String),
}

impl Chromedriver {
    /// Starts a chromedriver on a port the system picks, waits until it
    /// says it listens, and returns it with its endpoint.
    pub(crate) async fn start() -> Result<(Self, String), Box<dyn Error>> {
        let binary = std::env::var_os(CHROMEDRIVER_ENV)
            .map(PathBuf::from)
            .or_else(|| installed().0)
            .unwrap_or_else(|| PathBuf::from(CHROMEDRIVER));
        Self::start_from(&binary).await
    }

    /// Starts the chromedriver `binary` as [`Chromedriver::start`] does,
    /// starting it again, at most [`STARTS`] times in all, while it exits
    /// because the port it picked for itself was bound already.
    async fn start_from(binary: &Path) -> Result<(Self, String), Box<dyn Error>> {
        let mut last = String::new();
        for _ in 0..STARTS {
            match Self::start_once(binary).await? {
                Start::Listening(chromedriver, port) => {
                    return Ok((*chromedriver, format!("http://127.0.0.1:{port}")));
                }
                // NOTE: no specification governs this: our own design; chromedriver picks the
                // port of `--port=0` itself, and a port another process took meanwhile is retried.
                Start::PortTaken(output) => last = output,
            }
        }
        Err(format!("chromedriver found its port bound already {STARTS} times:\n{last}").into())
    }

    /// Starts the chromedriver `binary` once and waits until it says it
    /// listens, or exits.
    async fn start_once(binary: &Path) -> Result<Start, Box<dyn Error>> {
        let stderr = NamedTempFile::new()?;
        let mut command = Command::new(binary);
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command
            .arg("--port=0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr.reopen()?))
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                format!(
                    "{} does not start (run scripts/release/journey-tools.sh target/journey-tools, or name chromedriver in {CHROMEDRIVER_ENV}): {error}",
                    binary.display()
                )
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or("chromedriver's standard output")?;
        let mut lines = BufReader::new(stdout).lines();
        let mut written = Vec::new();
        let port = tokio::time::timeout(WAIT, async {
            while let Some(line) = lines.next_line().await? {
                if let Some(port) = line.strip_prefix(LISTENING) {
                    return Ok::<Option<u16>, Box<dyn Error>>(Some(
                        port.trim_end_matches('.').parse::<u16>()?,
                    ));
                }
                written.push(line);
            }
            Ok(None)
        })
        .await
        .map_err(|_elapsed| format!("chromedriver never listened within {WAIT:?}"))??;
        if let Some(port) = port {
            let chromedriver = Self {
                child,
                _stdout: lines,
                _stderr: stderr,
            };
            return Ok(Start::Listening(Box::new(chromedriver), port));
        }
        tokio::time::timeout(WAIT, child.wait())
            .await
            .map_err(|_elapsed| {
                format!("chromedriver closed its output and never exited within {WAIT:?}")
            })??;
        written.push(std::fs::read_to_string(stderr.path())?);
        let output = written.join("\n");
        if output.contains(PORT_TAKEN) {
            return Ok(Start::PortTaken(output));
        }
        Err(format!("chromedriver exited before it listened:\n{output}").into())
    }
}

impl Drop for Chromedriver {
    /// Kills the chromedriver's process group: the driver, and every Chrome
    /// process it started.
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(group) = self
            .child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(rustix::process::Pid::from_raw)
        {
            // NOTE: no specification governs this: our own design; a group
            // that has already exited (ESRCH) leaves nothing to stop.
            let _stopped: rustix::io::Result<()> =
                rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
    }
}

/// Fake chromedrivers: shell scripts that answer `--port=0` the way
/// chromedriver does, to hold the start to its retry rule without a browser.
#[cfg(unix)]
mod fake {
    use std::error::Error;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use super::{Chromedriver, STARTS};

    /// Writes the script `body` as an executable `chromedriver` in `dir`.
    fn script(dir: &Path, body: &str) -> Result<PathBuf, Box<dyn Error>> {
        let path = dir.join("chromedriver");
        std::fs::write(&path, format!("#!/bin/sh\n{body}"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        Ok(path)
    }

    /// How many times a script in `dir` ran, by the lines it appended to
    /// `runs`.
    fn runs(dir: &Path) -> Result<usize, Box<dyn Error>> {
        Ok(std::fs::read_to_string(dir.join("runs"))?.lines().count())
    }

    /// A script that counts its runs, finds its port bound on the first
    /// `taken` of them, and listens on port 4444 after.
    fn taken_then_listening(dir: &Path, taken: u32) -> Result<PathBuf, Box<dyn Error>> {
        let runs = dir.join("runs");
        script(
            dir,
            &format!(
                "echo run >> '{runs}'\n\
                 if [ \"$(wc -l < '{runs}')\" -le {taken} ]; then\n\
                 echo '[1.0][SEVERE]: bind() failed: Address already in use (98)' >&2\n\
                 exit 1\n\
                 fi\n\
                 echo 'ChromeDriver was started successfully on port 4444.'\n\
                 exec sleep 30\n",
                runs = runs.display()
            ),
        )
    }

    #[tokio::test]
    async fn a_port_bound_already_starts_chromedriver_again() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let binary = taken_then_listening(dir.path(), 2).expect("a fake chromedriver");
        let (chromedriver, endpoint) = Chromedriver::start_from(&binary)
            .await
            .expect("the third start listens");
        drop(chromedriver);
        assert_eq!(endpoint, "http://127.0.0.1:4444");
        assert_eq!(runs(dir.path()).expect("the runs"), 3);
    }

    #[tokio::test]
    async fn a_port_bound_on_every_start_fails_after_the_last() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let binary = taken_then_listening(dir.path(), STARTS).expect("a fake chromedriver");
        let error = Chromedriver::start_from(&binary)
            .await
            .expect_err("every start finds its port bound");
        assert!(
            error.to_string().contains("Address already in use"),
            "{error}"
        );
        assert_eq!(
            runs(dir.path()).expect("the runs"),
            usize::try_from(STARTS).expect("a count")
        );
    }

    #[tokio::test]
    async fn another_early_exit_fails_at_once_with_its_output() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let runs_file = dir.path().join("runs");
        let binary = script(
            dir.path(),
            &format!(
                "echo run >> '{}'\necho 'no Chrome binary' >&2\nexit 1\n",
                runs_file.display()
            ),
        )
        .expect("a fake chromedriver");
        let error = Chromedriver::start_from(&binary)
            .await
            .expect_err("chromedriver exits before it listens");
        let message = error.to_string();
        assert!(
            message.contains("exited before it listened") && message.contains("no Chrome binary"),
            "{message}"
        );
        assert_eq!(runs(dir.path()).expect("the runs"), 1);
    }
}
