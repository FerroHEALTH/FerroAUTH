#!/usr/bin/env bash
# SPDX-FileCopyrightText: Cadasto B.V.
# SPDX-License-Identifier: BUSL-1.1
#
# book-csp.sh: give every page of the built book its own
# Content-Security-Policy, with no 'unsafe-inline'.
#
#   scripts/site/book-csp.sh BOOK_DIR
#
# mdBook writes six or seven inline <script> blocks into each page (the theme
# and sidebar bootstrap, the path to the site root) and two style attributes
# ("clear: both", and the page breaks of print.html). The landing page's
# policy, script-src 'self' and style-src 'self', would block all of them. So
# this script reads each page after mdBook has written it, hashes every inline
# script and every style attribute, and writes a policy that allows exactly
# those, by SHA-256, and nothing else inline. The style attributes the bundled
# scripts set with setAttribute('style', ...) are hashed as well, read from the
# JavaScript the book ships.
#
# The policy travels in a <meta http-equiv> because GitHub Pages sets no
# response headers, and it goes first in <head>, because a meta policy governs
# only what the parser meets after it. A page without `<meta charset="UTF-8">`
# is an mdBook template this script does not know, and it fails rather than
# guess. Running it twice gives the same result.

set -euo pipefail

readonly BOOK="${1:?usage: $0 BOOK_DIR}"
[[ -d "$BOOK" ]] || { echo "book-csp: no such directory: $BOOK" >&2; exit 1; }

# Every style value a bundled script sets through setAttribute, one per line.
script_styles="$(find "$BOOK" -name '*.js' -exec perl -0777 -ne '
  while (/setAttribute\(\s*["\x27]style["\x27]\s*,\s*(["\x27])(.*?)\1\s*\)/gs) { print "$2\n" }
' {} + | sort -u)"

count=0
while IFS= read -r page; do
  SCRIPT_STYLES="$script_styles" perl -0777 -i -pe '
    use Digest::SHA qw(sha256_base64);
    sub h { my $d = sha256_base64($_[0]); $d .= "=" while length($d) % 4; "\x27sha256-$d\x27" }

    # Drop a policy an earlier run wrote, so the hashes are taken over the
    # page as mdBook left it.
    s{\n[ \t]*<meta http-equiv="Content-Security-Policy"[^>]*>}{}g;
    s{\n[ \t]*<meta name="referrer"[^>]*>}{}g;

    my (%script, %style);
    while (m{<script(\s[^>]*)?>(.*?)</script>}gs) {
      my ($attrs, $body) = ($1 // "", $2);
      next if $attrs =~ /\bsrc\s*=/;
      next if $attrs =~ /\btype\s*=\s*"application\/(ld\+)?json"/;
      $script{h($body)} = 1;
    }
    while (m{<style(\s[^>]*)?>(.*?)</style>}gs) { $style{h($2)} = 1 }
    my $attr_styles = 0;
    while (m{\sstyle="([^"]*)"}g) {
      die "book-csp: a style attribute carries an entity, which this script does not decode: $1\n" if $1 =~ /&/;
      $style{h($1)} = 1; $attr_styles = 1;
    }
    for my $v (split /\n/, $ENV{SCRIPT_STYLES} // "") { $style{h($v)} = 1; $attr_styles = 1 }

    my $script_src = join " ", "\x27self\x27", sort keys %script;
    my $style_src = join " ", "\x27self\x27", ($attr_styles ? "\x27unsafe-hashes\x27" : ()), sort keys %style;
    my $policy = "default-src \x27self\x27; script-src $script_src; style-src $style_src; "
      . "img-src \x27self\x27 data:; font-src \x27self\x27; connect-src \x27self\x27; "
      . "object-src \x27none\x27; base-uri \x27self\x27; form-action \x27none\x27; frame-ancestors \x27none\x27";

    s{(<meta charset="UTF-8">)}{$1\n        <meta http-equiv="Content-Security-Policy" content="$policy">\n        <meta name="referrer" content="strict-origin-when-cross-origin">}
      or die "book-csp: no <meta charset=\"UTF-8\"> to anchor the policy after\n";
  ' "$page"
  count=$((count + 1))
done < <(find "$BOOK" -name '*.html')

echo "book-csp: $count pages carry a hashed policy."
