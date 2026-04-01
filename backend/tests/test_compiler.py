"""Tests for app/services/compiler.py — _slugify and filename generation."""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import pytest

from app.services.compiler import _slugify
from app.core.constants import FILENAME_MAX_SLUG_LENGTH


# ---------------------------------------------------------------------------
# _slugify — basic transformations
# ---------------------------------------------------------------------------

class TestSlugifyBasic:
    """Normal-case transformations."""

    def test_spaces_become_underscores(self):
        assert _slugify("John Doe") == "John_Doe"

    def test_multiple_spaces(self):
        assert _slugify("New  York  City") == "New__York__City"

    def test_alphanumeric_passthrough(self):
        assert _slugify("abc123XYZ") == "abc123XYZ"

    def test_hyphens_preserved(self):
        assert _slugify("front-end") == "front-end"

    def test_underscores_preserved(self):
        assert _slugify("my_file") == "my_file"


# ---------------------------------------------------------------------------
# _slugify — special characters stripped
# ---------------------------------------------------------------------------

class TestSlugifySpecialChars:
    """Characters outside [a-zA-Z0-9_-] must be stripped."""

    def test_apostrophe_and_ampersand(self):
        assert _slugify("O'Brien & Co.") == "OBrien__Co"

    def test_parentheses_and_brackets(self):
        assert _slugify("React (v18) [beta]") == "React_v18_beta"

    def test_commas_and_semicolons(self):
        assert _slugify("Python, Java; Go") == "Python_Java_Go"

    def test_at_sign_and_hash(self):
        assert _slugify("user@host#root") == "userhostroot"

    def test_dollar_and_percent(self):
        assert _slugify("100% $profit") == "100_profit"


# ---------------------------------------------------------------------------
# _slugify — security / adversarial inputs
# ---------------------------------------------------------------------------

class TestSlugifySecurity:
    """Inputs that try to escape the filename sandbox."""

    def test_path_traversal_dots_and_slashes(self):
        result = _slugify("../../etc/passwd")
        assert "/" not in result
        assert ".." not in result
        assert result == "etcpasswd"

    def test_null_bytes_stripped(self):
        result = _slugify("file\x00name")
        assert "\x00" not in result
        assert result == "filename"

    def test_shell_metacharacters(self):
        dangerous = "$(rm -rf /); `echo pwned` | cat > /dev/null"
        result = _slugify(dangerous)
        # Nothing dangerous should survive the allowlist
        assert "$" not in result
        assert "`" not in result
        assert ";" not in result
        assert "|" not in result
        assert ">" not in result
        assert "/" not in result
        # Only alphanumeric, underscore, hyphen remain
        assert re.match(r"^[a-zA-Z0-9_-]*$", result)

    def test_backslashes_stripped(self):
        assert _slugify("C:\\Users\\admin") == "CUsersadmin"

    def test_newlines_and_tabs_stripped(self):
        result = _slugify("line1\nline2\ttab")
        assert "\n" not in result
        assert "\t" not in result
        assert result == "line1line2tab"


# ---------------------------------------------------------------------------
# _slugify — unicode handling
# ---------------------------------------------------------------------------

class TestSlugifyUnicode:
    """Non-ASCII characters are stripped by the allowlist regex."""

    def test_accented_characters_stripped(self):
        # 'R' stays, 'é' stripped, 's' stays, 'u' stays, 'm' stays, 'é' stripped
        assert _slugify("Résumé") == "Rsum"

    def test_cjk_characters_stripped(self):
        assert _slugify("日本語テスト") == ""

    def test_emoji_stripped(self):
        assert _slugify("hello🚀world") == "helloworld"

    def test_mixed_ascii_unicode(self):
        assert _slugify("José García") == "Jos_Garca"


# ---------------------------------------------------------------------------
# _slugify — edge cases
# ---------------------------------------------------------------------------

class TestSlugifyEdgeCases:
    """Empty, whitespace-only, and boundary-length inputs."""

    def test_empty_string(self):
        assert _slugify("") == ""

    def test_whitespace_only(self):
        # Spaces become underscores, so "   " -> "___"
        assert _slugify("   ") == "___"

    def test_all_special_chars(self):
        assert _slugify("!@#$%^&*()") == ""


# ---------------------------------------------------------------------------
# _slugify — truncation (max_len)
# ---------------------------------------------------------------------------

class TestSlugifyTruncation:
    """Output must not exceed max_len (default FILENAME_MAX_SLUG_LENGTH = 50)."""

    def test_long_string_truncated_to_default(self):
        long_input = "A" * 200
        result = _slugify(long_input)
        assert len(result) == FILENAME_MAX_SLUG_LENGTH
        assert result == "A" * FILENAME_MAX_SLUG_LENGTH

    def test_custom_max_len(self):
        result = _slugify("Hello World This Is Long", max_len=10)
        assert len(result) <= 10
        assert result == "Hello_Worl"

    def test_max_len_zero(self):
        assert _slugify("anything", max_len=0) == ""

    def test_exact_boundary_length(self):
        input_text = "x" * FILENAME_MAX_SLUG_LENGTH
        assert len(_slugify(input_text)) == FILENAME_MAX_SLUG_LENGTH

    def test_one_over_boundary(self):
        input_text = "x" * (FILENAME_MAX_SLUG_LENGTH + 1)
        assert len(_slugify(input_text)) == FILENAME_MAX_SLUG_LENGTH

    def test_stripping_happens_before_truncation(self):
        # 60 chars with interspersed dots: dots are stripped first, then truncate
        input_text = ("ab." * 40)  # 120 chars raw, 80 after stripping dots
        result = _slugify(input_text)
        assert len(result) == FILENAME_MAX_SLUG_LENGTH
        assert "." not in result


# ---------------------------------------------------------------------------
# Filename generation (compile_pdf slug assembly)
# ---------------------------------------------------------------------------

class TestFilenameGeneration:
    """Verify the slug-assembly logic used inside compile_pdf.

    We replicate the slug-building logic here to test it without
    invoking pdflatex.
    """

    @staticmethod
    def _build_filename(person_name="", company_name="", role_title=""):
        """Mirror the slug logic from compile_pdf."""
        name_slug = _slugify(person_name) if person_name else "Resume"
        slug_parts = []
        if company_name:
            slug_parts.append(_slugify(company_name))
        if role_title:
            slug_parts.append(_slugify(role_title))
        slug = "_".join(slug_parts)[:FILENAME_MAX_SLUG_LENGTH]
        unique_id = "abcd1234"  # deterministic stand-in for uuid
        return f"{name_slug}_{slug}_{unique_id}" if slug else f"{name_slug}_{unique_id}"

    def test_full_filename(self):
        name = self._build_filename("John Doe", "Acme Corp", "Backend Engineer")
        assert name == "John_Doe_Acme_Corp_Backend_Engineer_abcd1234"

    def test_no_company_no_role(self):
        name = self._build_filename("Jane Smith")
        assert name == "Jane_Smith_abcd1234"

    def test_no_person_name_defaults_to_resume(self):
        name = self._build_filename("", "Google", "SWE")
        assert name == "Resume_Google_SWE_abcd1234"

    def test_all_empty_defaults(self):
        name = self._build_filename()
        assert name == "Resume_abcd1234"

    def test_special_chars_in_all_fields(self):
        name = self._build_filename("O'Brien", "AT&T", "Sr. Dev (Lead)")
        assert "'" not in name
        assert "&" not in name
        assert "(" not in name
        assert ")" not in name
        assert "." not in name
