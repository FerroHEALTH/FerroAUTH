<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# FerroSMART brand

FerroSMART follows the FerroHEALTH family system and takes its own mark and its
own hue, as every product in the family does. The file set, the naming and the
variants are shared with the family; the mark and the palette are FerroSMART's
own. Everything here is under the Business Source License 1.1 with the rest of
the repository.

## The mark

A shield with a keyhole. The server is the gate that decides whether a token
may do what it asks; the shield is the full hue and the keyhole the light
value, so the gate reads as one at favicon sizes.

## Palette

FerroSMART's hue is the yellow `#FBBF24`. Yellow carries no text on a light
ground (1.6:1 against the surface), so on a light ground the brand speaks in
bronze, the deep shade of the same hue, and the yellow stays in the keyhole
and in fills that carry ink.

| Token | Hex | Use |
|---|---|---|
| bronze | `#78350F` | the mark and accents on a light ground; text on light (8.7:1 on the surface) |
| bronze-light | `#FBBF24` | the yellow: the mark and accents on a dark ground (11.3:1 on the tile); the keyhole on a light ground; a fill under ink (10.7:1) |
| ink | `#0F172A` | text on light |
| mist | `#F1F5F9` | text on dark |
| tile | `#0B1020` | dark tile background |
| surface | `#F8FAFC` | light surface background |

The hue was chosen by measurement against the hues the family already owns:
worst-case CIEDE2000 distance over both grounds and normal, protanope and
deuteranope vision. The numbers and the bar are recorded in the family
repository's `assets/brand/README.md`, and the family site copies the two hue
values from `tokens.css` here verbatim.

## The lockups

FerroSMART is a FerroHEALTH product (owner decision 2026-11-17), so its
lockups take its own hue, as every product's do. On a light ground the
shield is bronze and the keyhole the yellow; on a dark ground the shield is
the yellow and the keyhole amber 100 (`#FEF3C7`, 17.0:1 on the tile). The
wordmark is set as the other products' are: "FerroSMART" in ink on a light
ground and mist on a dark one, with the construction and the type of
FerroHEALTH's `assets/brand/ferrohealth-lockup-auto.svg`.

## Files

| File | What it is |
|---|---|
| `ferrosmart-icon.svg` | primary icon, full colour, transparent background, 64-unit viewBox at a 512 intrinsic size |
| `tokens.css` | the palette as CSS custom properties |
| `ferrosmart-lockup-auto.svg` | the shield beside the wordmark for the README and any page that serves one file to both themes, switched on `prefers-color-scheme` |
| `ferrosmart-lockup-light.svg` | the lockup for a light ground |
| `ferrosmart-lockup-dark.svg` | the lockup for a dark ground |

The favicon set and the social card follow when the product has a site to
carry them.
