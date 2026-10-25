<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# FerroAUTH brand

FerroAUTH follows the FerroHEALTH family system and takes its own mark and its
own hue, as every product in the family does. The file set, the naming and the
variants are shared with the family; the mark and the palette are FerroAUTH's
own. Everything here is under the Business Source License 1.1 with the rest of
the repository.

## The mark

A shield with a keyhole. The server is the gate that decides whether a token may do what it asks; the shield is the full hue and the keyhole the light value, so the gate reads as one at favicon sizes.

## Palette, "Bronze & Iron"

| Token | Hex | Use |
|---|---|---|
| bronze | `#78350F` | primary mark and accents; text on light |
| bronze-light | `#FBBF24` | the same voice on a dark ground; highlights in the mark |
| ink | `#0F172A` | text on light |
| mist | `#F1F5F9` | text on dark |
| tile | `#0B1020` | dark tile background |
| surface | `#F8FAFC` | light surface background |

The hue was chosen by measurement against the hues the family already owns:
worst-case CIEDE2000 distance over both grounds and normal, protanope and
deuteranope vision. The numbers and the bar are recorded in the family
repository's `assets/brand/README.md`, and the family site copies the two hue
values from `tokens.css` here verbatim.

## Files

| File | What it is |
|---|---|
| `ferroauth-icon.svg` | primary icon, full colour, transparent background, 64-unit viewBox at a 512 intrinsic size |
| `tokens.css` | the palette as CSS custom properties |
| `ferroauth-lockup-auto.svg` | the mark and the wordmark side by side for the README: the shield in bronze and the keyhole in bronze-light on a light ground, the shield in bronze-light and the keyhole in mist on a dark ground, switched on `prefers-color-scheme` |

The favicon set and the social card follow when the product has a site to
carry them.
