"""Centralized constants — no magic numbers in service code."""

# Upload limits
MAX_UPLOAD_SIZE = 2 * 1024 * 1024  # 2 MB
MIN_TEX_SIZE = 100  # chars — reject trivially small files
MIN_JD_LENGTH = 50  # chars — minimum JD length

# Truncation
TEX_TRUNCATE_LENGTH = 15_000  # chars sent to LLM for resume analysis
JD_TRUNCATE_LENGTH = 4_000  # chars sent to LLM for keyword extraction

# LLM
DEFAULT_LLM_MODEL = "gpt-4o-mini"
GEMINI_MODEL = "gemini-2.0-flash"
MAX_OPENAI_FAILURES = 5

# Compilation
PDFLATEX_TIMEOUT = 30  # seconds per pdflatex pass

# Rate limiting
RATE_LIMIT_PER_MINUTE = 10

# Filename
FILENAME_MAX_SLUG_LENGTH = 50

# Pipeline step labels (used by SSE progress events)
PIPELINE_STEP_LABELS = [
    "Analyzing resume...",
    "Extracting keywords...",
    "Matching skills...",
    "Computing reorder plan...",
    "Injecting into LaTeX...",
    "Compiling PDF...",
]
