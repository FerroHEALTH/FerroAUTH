// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `ferrosmart` binary: a thin entry point over the library run path.

fn main() -> std::process::ExitCode {
    ferrosmart::command::RUN.run(std::env::args(), ferrosmart::command::dispatch)
}
