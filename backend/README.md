# Resume Tailor — Backend

FastAPI service that takes a LaTeX resume + job description and returns a tailored PDF with skills reordered and keywords injected.

## Setup

### Prerequisites

- Python 3.11+
- pdflatex (for PDF generation — see below)

### Why pdflatex?

The pipeline's final step (Step 5) compiles the tailored `.tex` file into a PDF using `pdflatex`. This is a command-line tool from the TeX Live distribution — it's **not** a Python package and can't be installed via pip.

- **With pdflatex**: The API returns the full response — keyword analysis, match score, reorder plan, diff, **plus** a base64-encoded PDF (`pdf_b64`) and the tailored LaTeX source (`tex_content`) for download.
- **Without pdflatex**: The API still works — all analysis fields are returned, but `pdf_b64` and `filename` will be empty. Useful for development/testing without needing a TeX installation.

### Installing pdflatex locally (macOS)

**Option A: BasicTeX (~100 MB)** — lightweight, recommended

```bash
brew install --cask basictex
```

After install, **restart your terminal** (or run `eval "$(/usr/libexec/path_helper)"`) for the TeX binaries to appear in your PATH.

BasicTeX is a minimal distribution — it includes `pdflatex` and core fonts but not every LaTeX package. Our resume template uses `enumitem` (custom lists) and `titlesec` (section formatting), which must be installed separately:

```bash
# Update the TeX package manager first (required after fresh install)
sudo /Library/TeX/texbin/tlmgr update --self

# Install the two packages our resume template needs
sudo /Library/TeX/texbin/tlmgr install enumitem titlesec
```

> **Why the full path?** `tlmgr` lives in `/Library/TeX/texbin/` which may not be in `sudo`'s PATH. Using the full path avoids `sudo: tlmgr: command not found`.

**Option B: Full MacTeX (~4 GB)** — includes everything, no extra packages needed

```bash
brew install --cask mactex-no-gui
```

### Installing pdflatex locally (Ubuntu/Debian)

```bash
sudo apt-get install texlive-base texlive-latex-extra
```

`texlive-latex-extra` includes `enumitem`, `titlesec`, and most other common packages.

### How pdflatex is resolved at runtime

The compiler (`app/services/compiler.py`) uses `_find_pdflatex()` to auto-detect the binary. No separate handling is needed per environment — the same code works everywhere:

| Environment | How `_find_pdflatex()` resolves |
|---|---|
| **Docker (Render/AWS)** | `shutil.which("pdflatex")` → `/usr/bin/pdflatex` |
| **macOS with BasicTeX** | `shutil.which` misses → falls back to `/Library/TeX/texbin/pdflatex` |
| **macOS with full MacTeX** | `shutil.which("pdflatex")` → finds it in PATH |
| **No TeX installed** | Both checks fail → `RuntimeError` with helpful message |

In Docker, `apt-get install texlive-base` puts `pdflatex` at `/usr/bin/pdflatex`, which is always in PATH. So `shutil.which("pdflatex")` finds it on the first check — the macOS fallback path never gets reached.

On macOS with BasicTeX, `/Library/TeX/texbin/` is often not in the shell PATH (especially under `sudo` or non-login shells). The fallback handles this automatically so you never need to set `PATH` manually when starting the server.

### Docker (Render deployment)

```bash
docker build -t resume-tailor-backend .
docker run -p 8001:8001 --env-file .env resume-tailor-backend
```

The Dockerfile installs `texlive-base` + `texlive-latex-extra` so pdflatex and all required LaTeX packages (`enumitem`, `titlesec`, etc.) work out of the box — no manual `tlmgr` steps needed.

### Install

```bash
cd resume-tailor/backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env — set your keys (see below)
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | **Yes** | — | OpenAI API key (GPT-4o-mini) — the only truly required key |
| `LANGFUSE_SECRET_KEY` | No | — | Langfuse secret key (enables prompt management + tracing) |
| `LANGFUSE_PUBLIC_KEY` | No | — | Langfuse public key |
| `LANGFUSE_HOST` | No | `https://cloud.langfuse.com` | Langfuse host URL |
| `GOOGLE_AI_API_KEY` | No | — | Gemini fallback (used if OpenAI fails 5 consecutive times) |
| `LLM_MODEL` | No | `gpt-4o-mini` | OpenAI model to use |
| `ALLOWED_ORIGINS` | No | `http://localhost:3000,http://localhost:3001` | CORS origins (comma-separated) |
| `AUTH_USERNAME` | No | — | UI auth gate username (empty = auth disabled) |
| `AUTH_PASSWORD` | No | — | UI auth gate password |
| `LOG_LEVEL` | No | `INFO` | Logging level |

> **Note:** `OPENAI_API_KEY` is the only required key. Without Langfuse keys, the app uses embedded fallback prompts and works normally — you just won't have prompt versioning or LLM tracing. Without `GOOGLE_AI_API_KEY`, there's no Gemini fallback if OpenAI is down.

### Run

```bash
uvicorn app.main:app --port 8001
```

### Verify

```bash
# Health check — should return {"status": "ok", "service": "resume-tailor", ...}
curl http://localhost:8001/api/health

# Interactive API docs
open http://localhost:8001/docs
```

If the health check returns `{"status": "ok"}`, the backend is running correctly.

- Health check: http://localhost:8001/api/health
- API docs: http://localhost:8001/docs

## API

### `POST /api/tailor`

Multipart form upload. Both `resume_file` and `jd_text` are required.

**Request (multipart/form-data):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resume_file` | File (.tex) | Yes | LaTeX resume file |
| `jd_text` | string | Yes | Job description (min 50 chars) |
| `job_title` | string | No | Job title (e.g., "Backend Developer") |
| `company_name` | string | No | Company name (e.g., "Acme Corp") |
| `user_instructions` | string | No | Custom instructions for tailoring (e.g., "Add Docker to skills, emphasize backend experience") |

**curl example:**
```bash
curl -X POST http://localhost:8001/api/tailor \
  -F "resume_file=@my_resume.tex" \
  -F "jd_text=We are looking for a Backend Developer with Python..." \
  -F "job_title=Backend Developer" \
  -F "company_name=Acme Corp" \
  -F "user_instructions=Emphasize backend and API experience"
```

**Response:**
```json
{
  "extracted": {
    "languages": ["Python"],
    "backend": ["Django", "FastAPI", "REST APIs"],
    "frontend": ["React.js"],
    "ai_llm": [],
    "databases": ["PostgreSQL"],
    "devops": ["Docker", "AWS"],
    "soft_skills": [],
    "domains": [],
    "role_title": "Backend Developer",
    "experience_level": "2+ years"
  },
  "match": {
    "matched": {"backend": ["Django", "FastAPI", "REST APIs"], "...": "..."},
    "missing_from_resume": {"backend": ["microservices"]},
    "injectable": {"backend": ["REST APIs"]},
    "total_jd_keywords": 10,
    "total_matched": 8,
    "match_score": 80,
    "dominant_category": "backend"
  },
  "reorder_plan": {
    "skills_category_order": ["backend", "devops", "languages", "..."],
    "project_order": ["chat_room", "react_agent", "..."],
    "summary_first_line": "Backend Developer with expertise in Django, FastAPI...",
    "experience_emphasis": {"zelthy": ["Django", "PostgreSQL"]}
  },
  "pdf_url": "/output/Ravi_Raj_Acme_Corp_Backend_Developer_a1b2c3d4.pdf",
  "pdf_b64": "JVBERi0xLjQK... (base64-encoded PDF bytes)",
  "tex_content": "\\documentclass[a4paper,10pt]{article}... (full tailored LaTeX source)",
  "tex_diff": "--- original\n+++ tailored\n...",
  "filename": "Ravi_Raj_Acme_Corp_Backend_Developer_a1b2c3d4",
  "pdf_error": "",
  "processing_time_ms": 50000
}
```

**Error responses:**

| Code | Cause |
|------|-------|
| 401 | Invalid credentials (auth gate enabled, wrong username/password) |
| 400 | Non-.tex file, non-UTF-8, file too small, invalid content-type |
| 413 | File too large (max 5 MB) |
| 422 | Missing required field, JD too short |
| 429 | Rate limit exceeded (10 requests/minute) |
| 500 | LLM call failed (resume analysis, extraction, or matching) |

### `POST /api/tailor-stream` (SSE)

Same inputs as `/api/tailor`, but returns a `text/event-stream` instead of JSON. Real-time progress events are emitted as each pipeline step completes.

**Request:** Identical to `/api/tailor` (multipart/form-data).

**SSE Events:**

```
event: progress
data: {"step": 0, "label": "Analyzing resume..."}

event: progress
data: {"step": 1, "label": "Extracting keywords..."}

event: progress
data: {"step": 2, "label": "Matching skills..."}

event: progress
data: {"step": 3, "label": "Computing reorder plan..."}

event: progress
data: {"step": 4, "label": "Injecting into LaTeX..."}

event: progress
data: {"step": 5, "label": "Compiling PDF..."}

event: complete
data: { ...full TailorResponse JSON... }
```

On pipeline failure, an `error` event is emitted instead of `complete`:

```
event: error
data: {"detail": "Resume analysis failed", "step": 0}
```

**Validation errors** (missing file, non-.tex, short JD) return normal HTTP responses (400/422), not SSE — the stream only opens after validation passes.

**PDF compilation failure** is non-fatal: the `complete` event is still sent, but `pdf_url` and `pdf_b64` will be empty strings. The `pdf_error` field will contain the pdflatex error message for display in the UI.

**Error responses** (before stream opens): Same as `/api/tailor` (400, 413, 422, 429).

### `POST /api/auth/verify`

Lightweight credential check for the frontend login gate. No body required — credentials are sent via headers.

**Request headers:**

| Header | Description |
|--------|-------------|
| `X-Auth-Username` | Username to verify |
| `X-Auth-Password` | Password to verify |

**Response:**
```json
{"valid": true, "auth_enabled": true}
```

If `AUTH_USERNAME` is empty (auth disabled): `{"valid": true, "auth_enabled": false}`.

### `GET /api/health`

```json
{"status": "ok", "service": "resume-tailor"}
```

## Project Structure

```
backend/
├── app/
│   ├── main.py              App setup, CORS, static files
│   ├── config.py            Pydantic Settings (env vars)
│   ├── models.py            Pydantic schemas + ResumeSections TypedDict
│   ├── middleware.py         Request-ID + password gate middleware
│   │
│   ├── core/
│   │   ├── constants.py     Magic numbers (limits, timeouts, sizes)
│   │   ├── llm.py           LLM client (OpenAI primary, Gemini fallback)
│   │   ├── langfuse_client.py  Prompt fetching + @observe tracing
│   │   └── logger.py        Structured logging
│   │
│   ├── routes/
│   │   ├── tailor.py        POST /api/tailor + /api/tailor-stream (SSE)
│   │   └── health.py        GET /api/health + POST /api/auth/verify
│   │
│   ├── services/
│   │   ├── resume_analyzer.py  Step 0: LLM extracts skills (cached by SHA-256)
│   │   ├── extractor.py        Step 1: LLM extracts JD keywords (cached by SHA-256)
│   │   ├── matcher.py          Step 2: LLM matches JD vs resume skills (+ user_instructions)
│   │   ├── reorderer.py        Step 3: Compute reorder plan (deterministic)
│   │   ├── injector.py         Step 4: Apply changes to LaTeX (deterministic)
│   │   └── compiler.py         Step 5: single-pass pdflatex → PDF
│   │
│   └── latex/
│       ├── parser.py        Deterministic marker insertion + parse sections
│       └── writer.py        Rewrite sections + LaTeX special char escaping
│
├── tests/
│   ├── conftest.py          Shared fixtures, rate limiter disable
│   ├── test_parser.py       LaTeX parser unit tests
│   ├── test_injector.py     Injector + writer tests
│   ├── test_reorderer.py    Reorder plan tests
│   ├── test_compiler.py     Slugify + filename generation tests
│   ├── test_endpoint.py     /api/tailor endpoint (mocked services)
│   ├── test_services.py     Extractor, matcher, analyzer (mocked LLM)
│   ├── test_stream_endpoint.py  /api/tailor-stream SSE endpoint tests
│   ├── test_routes.py       Route validation + CORS header tests
│   └── test_middleware.py   Rate limiter + request-ID middleware tests
│
├── output/                  Generated PDFs + .tex files (gitignored)
├── scripts/
│   └── push_prompts.py      Push all 3 prompts to Langfuse
├── Dockerfile               Render deployment (includes texlive)
├── requirements.txt
├── .env.example
└── .gitignore
```

## Pipeline Detail

### Step 0: Resume Analysis (`resume_analyzer.py` + `parser.py`)

Two sub-steps:

**0a. Skill extraction (LLM — cached by SHA-256 of .tex content, max 20 entries):**
- Sends the .tex to GPT-4o-mini to extract skills by category
- Returns `ResumeAnalysis(marked_tex, skills, sections_found, person_name)`
- On cache hit (same resume uploaded again), skips the LLM call entirely

**0b. Deterministic marker insertion (`parser.py` — no LLM):**
- `insert_section_markers()` uses regex to add comment markers to the ORIGINAL .tex
- Preserves ALL original LaTeX content — only inserts comment lines
- Detects `\section{...}` commands and maps them to marker types (SUMMARY, SKILLS, EXPERIENCE, PROJECTS)
- Adds sub-markers for skill categories (`% SKILL_CAT:backend`), experience entries (`% EXP:zelthy`), and projects (`% PROJECT:rag_engine`)

This architecture ensures the original LaTeX formatting (section headers, custom commands, spacing) is never modified by the LLM.

### Step 1: JD Extraction (`extractor.py`)

Parses the job description into structured categories:
- `languages`, `backend`, `frontend`, `ai_llm`, `databases`, `devops`, `soft_skills`, `domains`
- Plus `role_title` and `experience_level`

Normalization: "React" → "React.js", "Postgres" → "PostgreSQL", etc.

**Cached** by SHA-256 of `jd_text + job_title` (max 50 entries). Re-runs with the same JD skip the LLM call.

### Step 2: Matching (`matcher.py`)

LLM-powered semantic matching — no alias tables. Handles:
- Exact match: "Python" = "Python"
- Alias match: "React" = "React.js"
- Semantic match: "container orchestration" ≈ "Kubernetes"
- Version match: "Python 3" = "Python"

Accepts optional `user_instructions` (e.g., "Add Docker to skills", "Emphasize AI experience") which are passed to the LLM prompt to influence matching decisions.

Produces three sets:
- **matched**: JD keywords the candidate has
- **missing_from_resume**: JD keywords the candidate doesn't have (genuine gaps)
- **injectable**: Matched skills not currently listed on the resume (can be added)

### Step 3: Reorder (`reorderer.py`)

Deterministic — no LLM. Produces:
- **Skills category order**: Sorted by JD match count (most relevant category first)
- **Project order**: Scored by keyword overlap with JD
- **Summary first line**: Role title + top 3-4 matched skills
- **Experience emphasis**: Top keywords per experience entry

### Step 4: Inject (`injector.py`)

Applies the reorder plan to the marked .tex:
- Reorders `% SKILL_CAT:` blocks
- Reorders `% PROJECT:` blocks
- Appends injectable keywords to relevant skill lines
- Replaces summary first line
- Returns modified .tex + unified diff

### Step 5: Compile (`compiler.py`)

Writes modified .tex → runs `pdflatex` once (single-pass — resumes don't need cross-references) → cleans up aux files → returns PDF filename + bytes.

Additional features:
- **`\skillline` auto-injection**: If the .tex uses `\skillline{}{}` but doesn't define the command, the compiler auto-injects `\newcommand{\skillline}[2]{\textbf{#1:} #2}` before `\begin{document}`
- **Auto-detection**: Checks PATH first, then `/Library/TeX/texbin/pdflatex` (macOS BasicTeX fallback). If pdflatex is not installed, logs a warning and returns empty `pdf_b64` — the rest of the response still works
- **Non-fatal failures**: PDF compilation errors are captured in the `pdf_error` response field rather than failing the entire request

## Langfuse

### Prompts

All 3 prompts are stored in Langfuse. No hardcoded prompts in service code.

| Prompt | Langfuse Name | Config |
|--------|---------------|--------|
| Resume analysis | `resume-tailor-analyze` | temp=0.1, max_tokens=8000 |
| JD extraction | `resume-tailor-extract` | temp=0.1, max_tokens=1000 |
| Skill matching | `resume-tailor-match` | temp=0.1, max_tokens=2000 |

Push/update prompts:
```bash
python scripts/push_prompts.py
```

### Tracing

Every LLM call is automatically traced via:
- `langfuse.openai.AsyncOpenAI` wraps all OpenAI calls
- `@observe(name="...")` decorator creates spans for each pipeline step
- `flush()` at the end of each request ensures traces are sent

Trace names match prompt names — click a trace in Langfuse to see the exact prompt version used.

## LLM Client

`core/llm.py` provides a singleton `LLMClient` with:

- **Primary**: OpenAI (GPT-4o-mini by default)
- **Fallback**: Google Gemini (if `GOOGLE_AI_API_KEY` is set)
- Auto-fallback after 5 consecutive OpenAI failures (counter resets after successful Gemini call)
- Retry via `tenacity` for transient errors (`TimeoutException`, `ConnectError`, `APITimeoutError`)
- Specific exception handling — catches `APIError`, `HTTPError`, `ValueError` (no broad `except Exception`)
- Two methods: `call()` for text, `call_json()` for structured JSON
- All calls traced via Langfuse-wrapped `AsyncOpenAI`

## Testing

```bash
python -m pytest tests/ -v
```

207 tests covering:

| Test File | What | Tests |
|-----------|------|-------|
| `test_parser.py` | LaTeX parser: extract markers, parse sub-blocks, section parsing, skill extraction | 36 |
| `test_injector.py` | Writer + injector: marker replacement, skill reorder/injection, project reorder, full pipeline | 33 |
| `test_reorderer.py` | Reorder plan: skill ordering, project scoring, summary generation, experience emphasis, edge cases | 39 |
| `test_compiler.py` | Slugify: sanitization, security (path traversal, shell injection), unicode, truncation, filename assembly | 33 |
| `test_endpoint.py` | `/api/tailor`: validation (missing file, wrong type, short JD, small file), happy path, service failures | 13 |
| `test_stream_endpoint.py` | `/api/tailor-stream`: SSE validation, progress events, complete event, error events, PDF failure | 14 |
| `test_services.py` | Services: extractor, matcher, analyzer with mocked LLM (success, failure, edge cases) | 23 |
| `test_routes.py` | Route-level: content-type validation, CORS headers, file size, encoding checks | 12 |
| `test_middleware.py` | Rate limiter bypass, request-ID propagation, password gate middleware | 4 |

All LLM-dependent tests use `unittest.mock` — no real API calls. Rate limiting is auto-disabled via `conftest.py`.

## Security

- **Auth gate**: Optional username + password middleware (`PasswordGateMiddleware`). Protects `/api/tailor*` endpoints. Disabled when `AUTH_USERNAME` is empty. Credentials sent via `X-Auth-Username` + `X-Auth-Password` headers
- **CORS**: Restricted to explicit origins (`ALLOWED_ORIGINS`), explicit headers (`Content-Type`, `Authorization`, `X-Request-ID`, `X-Auth-Username`, `X-Auth-Password`)
- **Content-type validation**: Upload endpoint rejects non-LaTeX MIME types before processing
- **Rate limiting**: 10 requests/minute per IP (sliding window, auto-disabled in tests)
- **File validation**: Size limits (min 50B, max 5MB), `.tex` extension check, UTF-8 encoding check
- **PDF compilation**: Runs in `asyncio.to_thread` to avoid blocking the event loop

## Extending the Pipeline

### Adding a New Skill Category

The pipeline currently supports these skill categories: `languages`, `backend`, `frontend`, `ai_llm`, `databases`, `devops`, `soft_skills`, `domains`.

To add a new category (e.g., `mobile`):

1. **`app/models.py`** — Add the field to `ExtractedKeywords` and `MatchResult`:
   ```python
   class ExtractedKeywords(BaseModel):
       # ... existing fields ...
       mobile: list[str] = []
   ```

2. **`app/services/reorderer.py`** — The reorderer auto-discovers categories from the match result, so no changes needed if the field follows the same pattern.

3. **Langfuse prompts** — Update the extraction and matching prompts to include the new category. Push updated prompts:
   ```bash
   python scripts/push_prompts.py
   ```

4. **`app/core/fallback_prompts.py`** — Update the embedded fallback prompts to include the new category.

5. **Frontend** — Add the category label in `frontend/src/lib/utils.ts` (`CATEGORY_LABELS` map).

6. **Tests** — Update `test_services.py` mock responses and `test_reorderer.py` test data.

### Changing the PDF Layout

The pipeline does **not** control the LaTeX layout — your uploaded `.tex` file defines the layout. The pipeline only:
- Reorders existing sections (skills, projects)
- Injects keywords into existing skill lines
- Replaces the summary first line

If you want a different PDF layout, modify your `.tex` template. The pipeline works with any LaTeX structure as long as Step 0 (resume analyzer) can identify sections.

**Requirements for your `.tex` file:**
- Must have identifiable sections (summary, skills, experience, projects)
- Must use standard LaTeX commands (`\section`, `\textbf`, `\begin{itemize}`, etc.)
- Must be UTF-8 encoded and under 2 MB
db changed