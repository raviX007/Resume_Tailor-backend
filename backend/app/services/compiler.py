"""Step 5: Compile modified .tex to PDF using pdflatex."""

import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from app.core.constants import PDFLATEX_TIMEOUT, FILENAME_MAX_SLUG_LENGTH
from app.core.logger import logger

OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "output"

# macOS BasicTeX installs pdflatex here, but it's often not in the default PATH.
_MACTEX_BIN = "/Library/TeX/texbin/pdflatex"


def _slugify(text: str, max_len: int = FILENAME_MAX_SLUG_LENGTH) -> str:
    """Sanitize text for use in filenames — strict allowlist."""
    return re.sub(r"[^a-zA-Z0-9_-]", "", text.replace(" ", "_"))[:max_len]


def _find_pdflatex() -> str:
    """Return the pdflatex binary path.

    Checks system PATH first, then falls back to the known macOS BasicTeX
    location so the server works without manually setting PATH.
    """
    path = shutil.which("pdflatex")
    if path:
        return path
    if Path(_MACTEX_BIN).exists():
        return _MACTEX_BIN
    raise RuntimeError(
        "pdflatex not found. Install a TeX distribution — see README for instructions."
    )


def compile_pdf(
    tex_content: str,
    company_name: str = "",
    role_title: str = "",
    person_name: str = "",
) -> tuple[str, bytes]:
    """Write modified .tex and compile to PDF.

    Compiles in a temp directory, copies only the final PDF to output/.
    Temp files are cleaned up automatically.

    Args:
        tex_content: The modified LaTeX content.
        company_name: Company name for filename slug.
        role_title: Role title for filename slug.
        person_name: Person's name from resume (for filename).

    Returns: (pdf_filename, pdf_bytes) — filename relative to output dir + raw PDF bytes.
    Raises RuntimeError if compilation fails.
    """
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Generate unique filename with sanitized slugs
    name_slug = _slugify(person_name) if person_name else "Resume"
    slug_parts = []
    if company_name:
        slug_parts.append(_slugify(company_name))
    if role_title:
        slug_parts.append(_slugify(role_title))
    slug = "_".join(slug_parts)[:FILENAME_MAX_SLUG_LENGTH]
    unique_id = uuid.uuid4().hex[:8]
    base_name = f"{name_slug}_{slug}_{unique_id}" if slug else f"{name_slug}_{unique_id}"

    # Ensure \skillline command is defined (the analyzer LLM may inject it)
    if r"\skillline" in tex_content and r"\newcommand{\skillline}" not in tex_content:
        # Insert definition right after \begin{document} or before first \section
        skillline_def = r"\newcommand{\skillline}[2]{\textbf{#1:} #2}"
        if r"\begin{document}" in tex_content:
            tex_content = tex_content.replace(
                r"\begin{document}",
                r"\begin{document}" + "\n" + skillline_def,
                1,
            )
        else:
            tex_content = skillline_def + "\n" + tex_content

    # Compile in a temp directory to avoid accumulating files
    with tempfile.TemporaryDirectory(prefix="resume_tailor_") as tmpdir:
        tmp_path = Path(tmpdir)
        tex_path = tmp_path / f"{base_name}.tex"
        tex_path.write_text(tex_content)

        # Resolve pdflatex binary once (checks PATH, then macOS default location)
        pdflatex_bin = _find_pdflatex()

        # Single-pass pdflatex — resumes have no cross-references or bibliography
        result = subprocess.run(
            [
                pdflatex_bin,
                "-interaction=nonstopmode",
                "-output-directory", str(tmp_path),
                str(tex_path),
            ],
            capture_output=True,
            text=True,
            timeout=PDFLATEX_TIMEOUT,
            cwd=str(tmp_path),
        )

        if result.returncode != 0:
                error_lines = [
                    line for line in result.stdout.split("\n")
                    if line.startswith("!") or "Error" in line
                ]
                error_msg = "\n".join(error_lines[:5]) if error_lines else result.stderr[-300:]
                logger.error(f"pdflatex failed:\n{error_msg}")
                raise RuntimeError(f"pdflatex compilation failed: {error_msg}")

        tmp_pdf = tmp_path / f"{base_name}.pdf"
        if not tmp_pdf.exists():
            raise RuntimeError("PDF was not generated")

        # Copy final PDF + .tex to output/ (for serving + debugging)
        pdf_dest = OUTPUT_DIR / f"{base_name}.pdf"
        tex_dest = OUTPUT_DIR / f"{base_name}.tex"
        shutil.copy2(tmp_pdf, pdf_dest)
        shutil.copy2(tex_path, tex_dest)

    # Temp directory (aux, log, out files) auto-deleted here

    pdf_bytes = pdf_dest.read_bytes()
    logger.info(f"PDF compiled: {pdf_dest.name} ({len(pdf_bytes)} bytes)")
    return pdf_dest.name, pdf_bytes
