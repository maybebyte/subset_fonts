#!/usr/bin/env python3
# Copyright (c) 2025 Ashlen <dev@anthes.is>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import argparse
import hashlib
import os
import re
import tempfile
import warnings
from io import BytesIO
from pathlib import Path

from fontTools.subset import Subsetter
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer


def parse_unicode_ranges(range_string: str) -> set[int]:
    """Parse Unicode range string (e.g., 'U+0-FF,U+131') into set of codepoints."""
    codepoints: set = set()

    for part in range_string.split(","):
        part = part.strip()
        if not part.startswith("U+"):
            continue

        hex_part = part[2:]

        if "-" in hex_part:
            start_hex, end_hex = hex_part.split("-")
            start = int(start_hex, 16)
            end = int(end_hex, 16)
            codepoints.update(range(start, end + 1))
        else:
            codepoints.add(int(hex_part, 16))

    return codepoints


LATIN = parse_unicode_ranges(
    "U+0-FF,U+131,U+152,U+153,U+2BB,U+2BC,U+2C6,U+2DA,U+2DC,U+2000-206F,"
    "U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD"
)

LATIN_EXTENDED = parse_unicode_ranges(
    "U+100-24F,U+259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+20AD-20CF,U+2113,"
    "U+2C60-2C7F,U+A720-A7FF"
)

CYRILLIC = parse_unicode_ranges("U+400-45F,U+490,U+491,U+4B0,U+4B1,U+2116")

CYRILLIC_EXTENDED = parse_unicode_ranges(
    "U+460-52F,U+1C80-1C88,U+20B4,U+2DE0-2DFF,U+A640-A69F,U+FE2E,U+FE2F"
)

GREEK = parse_unicode_ranges("U+370-3FF")

GREEK_EXTENDED = parse_unicode_ranges("U+1F00-1FFF")

VIETNAMESE = parse_unicode_ranges(
    "U+102,U+103,U+110,U+111,U+128,U+129,U+168,U+169,U+1A0,U+1A1,U+1AF,"
    "U+1B0,U+1EA0-1EF9,U+20AB"
)

CRITICAL_FOFT = parse_unicode_ranges(
    "U+20-23,U+25-29,U+2C-3B,U+3F-5A,U+61-7A,U+2013,U+2014,U+2018,U+2019,U+201C,U+201D,U+2022,U+2026"
)

CRITICAL_FOFT_CODE = parse_unicode_ranges("U+20-7E")

DEFAULT_MAX_FONT_SIZE = 20 * 1024 * 1024  # 20MB


def validate_file_size(
    file_path: Path, max_size: int = DEFAULT_MAX_FONT_SIZE
) -> None:
    """Validate file size doesn't exceed limits to prevent resource exhaustion."""
    file_size = file_path.stat().st_size
    if file_size > max_size:
        size_mb = file_size / (1024 * 1024)
        limit_mb = max_size / (1024 * 1024)
        raise ValueError(
            f"Font file too large: {size_mb:.1f}MB exceeds {limit_mb:.1f}MB limit"
        )


def validate_unicode_ranges(unicode_ranges: set[int]) -> set[int]:
    """Filter and validate Unicode codepoints, excluding surrogates."""
    if not unicode_ranges:
        raise ValueError("Unicode ranges cannot be empty")

    valid_codepoints = {
        cp
        for cp in unicode_ranges
        if 0 <= cp <= 0x10FFFF and not (0xD800 <= cp <= 0xDFFF)
    }

    if not valid_codepoints:
        raise ValueError("No valid Unicode codepoints provided")

    return valid_codepoints


def get_font_codepoints(font: TTFont) -> set[int]:
    """Extract all available Unicode codepoints from font's character map."""
    if not font:
        raise ValueError("Font cannot be empty")

    if "cmap" not in font:
        raise ValueError("Font missing character mapping table")

    cmap = font.getBestCmap()
    if not cmap:
        raise ValueError("Font has no Unicode character mapping")

    return validate_unicode_ranges(cmap.keys())


def create_safe_output_path(output_dir: Path, filename: str) -> Path:
    """Create and validate output path within safe directory."""
    if not filename:
        raise ValueError("Filename cannot be empty")

    output_path = output_dir / filename

    if not output_path.suffix:
        raise ValueError(
            f"Output path must include file extension: {output_path}"
        )
    if output_path.exists() and not output_path.is_file():
        raise ValueError(
            f"Output path already exists and is not a file: {output_path}"
        )

    try:
        output_path.resolve().relative_to(output_dir.resolve())
    except ValueError as e:
        raise ValueError(
            f"Output path {output_path} is outside directory {output_dir}"
        ) from e

    return output_path


def generate_file_hash(font_data: bytes) -> str:
    """Generate SHA256 hash of font data for cache-busting filenames."""
    if not font_data:
        raise ValueError("Font data cannot be empty")

    return hashlib.sha256(font_data).hexdigest()


def normalize_string(text: str) -> str:
    """Create a normalized string for file and directory use."""
    if not text:
        raise ValueError("Input text cannot be empty")

    transformed_text = text.strip().lower()
    transformed_text = transformed_text.replace(" ", "-")
    transformed_text = re.sub(r"[^a-z0-9\-]", "", transformed_text)

    return transformed_text


def create_filename(
    font_family: str,
    variant: str,
    charset: str,
    font_hash: str,
    extension: str = "woff2",
) -> str:
    """Create filename with hash for cache busting."""
    if not re.match(r"^[a-f0-9]{64}$", font_hash):
        raise ValueError("Invalid SHA256 hash format")

    family = normalize_string(font_family)
    variant_name = normalize_string(variant)
    charset_name = normalize_string(charset)

    if not (family, variant_name, charset_name):
        raise ValueError(
            "Font family, variant, and charset must contain valid characters"
        )

    return f"{family}-{variant_name}-{charset_name}-{font_hash}.{extension}"


def save_font_file(font_data: bytes, output_path: Path) -> None:
    """Save font data to file atomically using write-and-rename pattern."""
    if not font_data:
        raise ValueError("Font data cannot be empty")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = ""

    with tempfile.NamedTemporaryFile(
        suffix=output_path.suffix, dir=output_path.parent, delete=False
    ) as temp_file:
        temp_file.write(font_data)
        temp_file.flush()
        os.fsync(temp_file.fileno())
        temp_path = temp_file.name

    os.replace(temp_path, output_path)


def load_font(font_path: Path) -> TTFont:
    """Load TTF/OTF font file into fonttools TTFont object."""
    validate_file_size(font_path)
    return TTFont(font_path)


def copy_font(font: TTFont) -> TTFont:
    """Create a deep copy of a font via serialization."""
    if not font:
        raise ValueError("Font cannot be empty")

    buffer = BytesIO()
    font.save(buffer)
    buffer.seek(0)
    return TTFont(buffer)


def get_font_family(font: TTFont) -> str:
    """Extract font family name from name table."""
    if not font or "name" not in font:
        raise ValueError("Font missing name table")

    name_table = font["name"]
    name = name_table.getBestFamilyName()  # type: ignore[attr-defined]
    return name if name else "Unknown"


def get_font_variant(font: TTFont) -> str:
    """Extract font variant/subfamily name from name table."""
    if not font or "name" not in font:
        raise ValueError("Font missing name table")

    name_table = font["name"]
    name = name_table.getBestSubFamilyName()  # type: ignore[attr-defined]
    return name if name else "Regular"


def validate_subset_result(
    original: TTFont, subset: TTFont, strict: bool = True
) -> None:
    """Validate that subsetting preserved essential font data."""
    if not original:
        raise ValueError("Original font cannot be empty")
    if not subset:
        raise ValueError("Subset font cannot be empty")

    if len(subset.getGlyphSet()) <= 1:
        raise ValueError(
            "Subsetting resulted in empty font - no requested characters found"
        )

    if "fvar" in original and "fvar" not in subset:
        message = "Subsetting removed variable font data (font is now static)"
        if strict:
            raise ValueError(message)
        warnings.warn(message)


def compress_to_woff2(font: TTFont) -> bytes:
    """Compress TTFont to WOFF2 format and return as bytes."""
    if not font:
        raise ValueError("Font cannot be empty")

    font_copy = copy_font(font)
    font_copy.flavor = "woff2"

    buffer = BytesIO()
    font_copy.save(buffer)

    return buffer.getvalue()


def subset_font(font: TTFont, unicode_ranges: set[int]) -> TTFont:
    """Create a subsetted copy of the font with only specified Unicode ranges."""
    if not font:
        raise ValueError("Font cannot be empty")
    if not unicode_ranges:
        raise ValueError("Unicode ranges cannot be empty")

    valid_codepoints = validate_unicode_ranges(unicode_ranges)
    font_copy = copy_font(font)

    subsetter = Subsetter()
    subsetter.options.harfbuzz_repacker = True
    subsetter.options.layout_features = ["*"]

    # Keep these name IDs to give proper attribution/credit where
    # it's due.
    #
    # 7: Trademark string.
    # 8: Manufacturer name.
    # 9: Designer name.
    # 11: URL of vendor.
    # 12: URL of designer.
    # 13: License description.
    # 14: License URL.
    #
    # https://learn.microsoft.com/en-us/typography/opentype/spec/name
    subsetter.options.name_IDs += [7, 8, 9, 11, 12, 13, 14]

    characters = "".join(chr(cp) for cp in valid_codepoints)
    subsetter.populate(text=characters)
    subsetter.subset(font_copy)

    validate_subset_result(font, font_copy)

    return font_copy


def create_critical_foft(font: TTFont, unicode_ranges: set[int]) -> TTFont:
    """Create Critical FOFT variant: static weight=400, minimal features, restricted charset."""
    if not font:
        raise ValueError("Font cannot be empty")
    if not unicode_ranges:
        raise ValueError("Unicode ranges cannot be empty")

    valid_codepoints = validate_unicode_ranges(unicode_ranges)
    font_copy = copy_font(font)

    if "fvar" in font_copy:
        instancer.instantiateVariableFont(
            font_copy, {"wght": 400}, inplace=True
        )

    subsetter = Subsetter()
    subsetter.options.harfbuzz_repacker = True
    subsetter.options.ignore_missing_unicodes = False
    subsetter.options.name_IDs += [7, 8, 9, 11, 12, 13, 14]

    characters = "".join(chr(cp) for cp in valid_codepoints)
    subsetter.populate(text=characters)
    subsetter.subset(font_copy)

    validate_subset_result(font, font_copy, strict=False)

    return font_copy


def get_all_charsets() -> dict[str, set[int]]:
    """Return all defined character sets as name -> codepoints mapping."""
    return {
        "latin": LATIN,
        "latin-extended": LATIN_EXTENDED,
        "cyrillic": CYRILLIC,
        "cyrillic-extended": CYRILLIC_EXTENDED,
        "greek": GREEK,
        "greek-extended": GREEK_EXTENDED,
        "vietnamese": VIETNAMESE,
        "critical-text": CRITICAL_FOFT,
        "critical-code": CRITICAL_FOFT_CODE,
    }


def process_font_for_charset(
    font: TTFont,
    charset_name: str,
    unicode_ranges: set[int],
    output_dir: Path,
) -> Path | None:
    """Process single font for one character set. Returns None if charset not supported."""
    font_family = get_font_family(font)
    font_variant = get_font_variant(font)

    try:
        if charset_name in ("critical-text", "critical-code"):
            subset_font_obj = create_critical_foft(font, unicode_ranges)
        else:
            subset_font_obj = subset_font(font, unicode_ranges)

        woff2_data = compress_to_woff2(subset_font_obj)
        font_hash = generate_file_hash(woff2_data)
        filename = create_filename(
            font_family, font_variant, charset_name, font_hash
        )

        output_path = create_safe_output_path(output_dir, filename)
        save_font_file(woff2_data, output_path)

        return output_path

    except ValueError:
        warnings.warn(
            f"Skipping {charset_name} charset for {font_family} {font_variant}:"
        )
        return None


def process_single_font(font: TTFont, output_dir: Path) -> list[Path]:
    """
    Process one loaded font through all available character sets including
    dynamic 'other'.
    """
    charsets = get_charsets_for_font(font, min_other_glyphs=1)
    successful_outputs = []

    for charset_name, unicode_ranges in charsets.items():
        output_path = process_font_for_charset(
            font, charset_name, unicode_ranges, output_dir
        )
        if output_path is not None:
            successful_outputs.append(output_path)

    return successful_outputs


def parse_arguments():
    """Parse and return command line arguments."""
    parser = argparse.ArgumentParser(
        description="Optimize fonts for web using Critical FOFT strategy"
    )
    parser.add_argument(
        "fonts",
        nargs="+",
        help="Font file(s) to process (.ttf, .otf, .woff, .woff2)",
    )
    parser.add_argument(
        "output_dir",
        help="Output directory (will be created if it doesn't exist)",
    )
    return parser.parse_args()


def validate_font_paths(font_paths: list[Path]) -> None:
    """Ensure all font paths exist and are files."""
    for font_path in font_paths:
        if not font_path.exists():
            raise FileNotFoundError(f"Font file not found: {font_path}")
        if not font_path.is_file():
            raise ValueError(f"Path is not a file: {font_path}")


def load_fonts_and_check_conflicts(
    font_paths: list[Path],
) -> dict[Path, TTFont]:
    """Load all fonts and check for family + variant conflicts."""
    loaded_fonts = {}
    processed_combinations: dict[tuple[str, str], Path] = {}

    for font_path in font_paths:
        font = load_font(font_path)
        family_name = normalize_string(get_font_family(font))
        variant_name = normalize_string(get_font_variant(font))

        combination_key = (family_name, variant_name)

        if combination_key in processed_combinations:
            existing_path = processed_combinations[combination_key]
            raise ValueError(
                f"Duplicate font variant: {family_name} {variant_name} "
                f"found in {font_path} and {existing_path}"
            )

        processed_combinations[combination_key] = font_path
        loaded_fonts[font_path] = font

    return loaded_fonts


def get_charsets_for_font(
    font: TTFont, min_other_glyphs: int = 1
) -> dict[str, set[int]]:
    """
    Get all character sets including font-specific 'other' charset for
    uncovered glyphs.
    """
    if not font:
        raise ValueError("Font cannot be empty")

    if min_other_glyphs < 1:
        raise ValueError("Minimum other glyphs must be positive")

    base_charsets = get_all_charsets()

    try:
        font_codepoints = get_font_codepoints(font)

        if not font_codepoints:
            warnings.warn("Font contains no valid Unicode codepoints")
            return base_charsets

        covered_codepoints = set()
        for charset_codepoints in base_charsets.values():
            covered_codepoints.update(charset_codepoints)

        other_codepoints = font_codepoints - covered_codepoints

        if len(other_codepoints) >= min_other_glyphs:
            base_charsets["other"] = other_codepoints
        elif other_codepoints:
            font_family = get_font_family(font)
            warnings.warn(
                f"Font {font_family} has {len(other_codepoints)} uncovered glyphs "
                f"(below threshold of {min_other_glyphs}), skipping 'other' subset"
            )

    except ValueError as e:
        font_family = get_font_family(font) if font else "unknown"
        warnings.warn(
            f"Could not calculate 'other' charset for {font_family}: {e}"
        )

    return base_charsets


def main():
    """Main CLI entry point for font optimization."""
    args = parse_arguments()

    output_dir = Path(args.output_dir)
    font_paths = [Path(font) for font in args.fonts]

    validate_font_paths(font_paths)

    loaded_fonts = load_fonts_and_check_conflicts(font_paths)
    output_dir.mkdir(parents=True, exist_ok=True)

    for font_path, font in loaded_fonts.items():
        print(f"Processing {font_path}...")

        family_dir_name = normalize_string(get_font_family(font))
        family_output_dir = output_dir / family_dir_name

        process_single_font(font, family_output_dir)

    print(f"\nFont optimization complete! Output saved to: {output_dir}")


if __name__ == "__main__":
    main()
