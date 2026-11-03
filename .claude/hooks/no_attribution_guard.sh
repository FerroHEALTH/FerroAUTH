#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
# .claude/hooks/no_attribution_guard.sh
#
# PreToolUse hook (matcher: Bash).
# Blocks a `git commit` or `gh pr create` BEFORE it runs when the text the
# commit or the pull request carries holds AI attribution, so it is removed
# rather than relying on the message being rewritten after the fact.
#
# Only that text is read (#195): a commit's `-m`/`--message` values and its
# `-F`/`--file` file, a pull request's `--title`/`-t` and `--body`/`-b`
# values and its `--body-file`/`-F` file, and the heredoc behind a `-F -` or
# `--body-file -`. Anything else the command does, such as writing a file,
# is not the commit's text and is not read.
#
#   no_attribution_guard.sh              reads the tool-call JSON on stdin
#   no_attribution_guard.sh --self-test
#
# Exit 2 blocks the tool call and returns the stderr text. Exit 0 allows it.

set -euo pipefail

# Prints the text the commit or the pull request of the tool-call JSON on
# stdin carries, or nothing for a command that makes neither.
carried_text() {
  perl -MJSON::PP -0777 -e '
    my $payload = eval { JSON::PP->new->decode(<STDIN>) } // {};
    my $command = $payload->{tool_input}{command} // "";
    my $cwd = $payload->{cwd} // ".";
    exit 0 unless $command =~ /git\s+commit|gh\s+pr\s+create/;
    $cwd = $1 if $command =~ /^\s*cd\s+([^\s;&|]+)/;
    my @text;
    my $value = qr{
        "((?:[^"\\]|\\.)*)"
      | \x27([^\x27]*)\x27
      | ([^\s;&|]+)
    }x;
    while ($command =~ /(?:^|\s)(?:-m|--message|--title|-t|--body|-b)(?:=|\s+)$value/g) {
      push @text, $1 // $2 // $3;
    }
    while ($command =~ /(?:^|\s)(?:-F|--file|--body-file)(?:=|\s+)$value/g) {
      my $path = $1 // $2 // $3;
      if ($path eq "-") {
        my $heredocs = $command;
        while ($heredocs =~ /<<-?\s*[\x27"]?(\w+)[\x27"]?\n(.*?)\n\1(?:\n|$)/gs) {
          push @text, $2;
        }
        next;
      }
      $path = "$cwd/$path" unless $path =~ m{^/};
      if (open my $fh, "<", $path) {
        local $/;
        push @text, scalar <$fh>;
      }
    }
    print join("\n", @text);
  '
}

# The attribution phrases refused, matched without regard to case.
readonly REFUSED='co-authored-by:.*(claude|anthropic|\[bot\])|generated[[:space:]]+with[[:space:]]+.*claude|generated[[:space:]]+by[[:space:]]+.*claude|claude[[:space:]]+code|🤖|assisted-by:.*claude|anthropic[[:space:]]+claude'

guard() {
  local text
  text="$(carried_text)"
  if printf '%s' "$text" | grep -qiE "$REFUSED"; then
    echo "BLOCKED: this commit or pull request carries AI attribution (Co-authored-by, 'Generated with …', 🤖, etc.). Remove all such lines from the message or description and retry. Commit and PR text describe only the change. This is a hard project rule." >&2
    return 2
  fi
  return 0
}

self_test() {
  local work tool trailer status
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  # The phrases are assembled here, so this file carries none of them.
  tool="Clau""de Co""de"
  trailer="Co-Authored""-By: Clau""de <noreply@example.org>"
  fail() {
    echo "no_attribution_guard: self-test FAILED: $*" >&2
    exit 1
  }
  # $1: the command; prints the guard's exit status for it.
  run() {
    local status=0
    perl -MJSON::PP -e 'print JSON::PP->new->encode({cwd => $ARGV[1], tool_input => {command => $ARGV[0]}})' "$1" "$work" |
      guard 2>/dev/null || status=$?
    printf '%s' "$status"
  }
  [[ "$(run "git commit -m \"fix: a change\" -m \"$trailer\"")" == 2 ]] || fail "a -m trailer passed"
  [[ "$(run "git commit -m \"\$(cat <<'EOF'
fix: a change

$trailer
EOF
)\"")" == 2 ]] || fail "a trailer in a -m heredoc passed"
  printf 'fix: a change\n\n%s\n' "$trailer" >"$work/message.txt"
  [[ "$(run "git commit -F message.txt")" == 2 ]] || fail "a trailer in a -F file passed"
  [[ "$(run "gh pr create --title \"a change\" --body \"Made with $tool\"")" == 2 ]] || fail "a PR body naming the tool passed"
  printf 'A change.\n\n🤖 Made by a tool\n' >"$work/body.md"
  [[ "$(run "gh pr create --title a --body-file body.md")" == 2 ]] || fail "a PR body file with the robot passed"
  [[ "$(run "gh pr create --title a --body-file - <<'EOF'
Made with $tool
EOF")" == 2 ]] || fail "a PR body heredoc behind --body-file - passed"
  status="$(run "cat > hook.sh <<'EOF'
# A hook for $tool
EOF
git add hook.sh && git commit -m \"ci: add a hook\"")"
  [[ "$status" == 0 ]] || fail "a file naming the tool, committed with a clean message, was refused"
  [[ "$(run "git push origin main # $tool")" == 0 ]] || fail "a push, which carries no message, was refused"
  [[ "$(run "ls # $trailer")" == 0 ]] || fail "a command that commits nothing was refused"
  echo "no_attribution_guard: self-test OK (a trailer in a -m value, a -m heredoc and a -F file refused, a PR title, body, body file and body heredoc read, a file written beside a clean commit, a push and other commands passed)."
}

case "${1:-}" in
  --self-test) self_test ;;
  "") guard ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac
