"""Main tailoring endpoint — .tex upload + JD text in, tailored PDF out."""

import asyncio
import base64
import json
import re
import time
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.models import TailorResponse
from app.services.resume_analyzer import analyze_uploaded_resume
from app.services.extractor import extract_keywords
from app.services.matcher import match_keywords
from app.services.reorderer import compute_reorder_plan
from app.services.injector import inject_into_latex
from app.services.compiler import compile_pdf
from app.latex.parser import parse_resume_sections, get_skills_on_resume, insert_section_markers
from app.core.langfuse_client import observe, flush
from app.core.constants import (
    MAX_UPLOAD_SIZE, MIN_TEX_SIZE, RATE_LIMIT_PER_MINUTE, PIPELINE_STEP_LABELS,
)
from app.core.logger import logger

router = APIRouter(prefix="/api", tags=["Tailor"])
limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class PipelineError(Exception):
    """Raised by _execute_pipeline when a step fails."""

    def __init__(self, status_code: int, detail: str, step: int):
        self.status_code = status_code
        self.detail = detail
        self.step = step
        super().__init__(detail)


def _sse_event(event: str, data: dict) -> str:
    """Format a single SSE event string."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _validate_upload(resume_file: UploadFile) -> str:
    """Validate and read the uploaded .tex file. Returns raw_tex string.

    Raises HTTPException on validation failure.
    """
    if not resume_file.filename or not resume_file.filename.endswith(".tex"):
        raise HTTPException(status_code=400, detail="Only .tex files are accepted")
    if resume_file.content_type and resume_file.content_type not in (
        "application/x-tex", "application/x-latex", "text/x-tex",
        "text/plain", "application/octet-stream",
    ):
        raise HTTPException(status_code=400, detail="Invalid file type — upload a .tex file")

    raw_bytes = await resume_file.read()
    if len(raw_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large (max {MAX_UPLOAD_SIZE // (1024 * 1024)}MB)",
        )

    try:
        raw_tex = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")

    if len(raw_tex.strip()) < MIN_TEX_SIZE:
        raise HTTPException(status_code=400, detail="File appears too small to be a valid LaTeX resume")

    return raw_tex


async def _execute_pipeline(
    raw_tex: str,
    jd_text: str,
    job_title: str,
    company_name: str,
    user_instructions: str = "",
    on_step: Callable[[int, str], Awaitable[None]] | None = None,
) -> TailorResponse:
    """Run the 6-step tailoring pipeline.

    Args:
        raw_tex: Validated UTF-8 .tex content.
        jd_text: Job description text.
        job_title: Optional job title.
        company_name: Optional company name.
        user_instructions: Optional user instructions for tailoring emphasis.
        on_step: Optional async callback invoked at the start of each step
                 with (step_index, step_label). Used by the SSE endpoint.

    Returns:
        TailorResponse with all results.

    Raises:
        PipelineError on step failure.
    """
    start = time.time()

    async def _emit(step: int) -> None:
        if on_step:
            await on_step(step, PIPELINE_STEP_LABELS[step])

    # Steps 0 + 1 in parallel — they're independent (resume vs JD)
    await _emit(0)
    analysis_task = analyze_uploaded_resume(raw_tex)
    extract_task = extract_keywords(jd_text, job_title)
    analysis, extracted = await asyncio.gather(analysis_task, extract_task)

    if not analysis:
        raise PipelineError(500, "Resume analysis failed — could not parse your .tex file", step=0)
    if not extracted:
        raise PipelineError(500, "Keyword extraction failed", step=1)

    await _emit(1)

    master_skills = analysis.skills
    person_name = analysis.person_name

    # Insert markers deterministically on the ORIGINAL tex — preserves formatting.
    # The LLM analysis is only used for skill extraction, not tex modification.
    marked_tex = insert_section_markers(raw_tex)

    # Parse the marked .tex into sections
    sections = parse_resume_sections(marked_tex)
    skills_on_resume = get_skills_on_resume(sections)

    # Step 2: Match JD keywords against resume skills via LLM
    await _emit(2)
    match = await match_keywords(extracted, master_skills, skills_on_resume, user_instructions)
    if not match:
        raise PipelineError(500, "Skill matching failed", step=2)

    # Step 3: Compute reorder plan
    await _emit(3)
    reorder_plan = compute_reorder_plan(extracted, match, sections)

    # Step 4: Inject into LaTeX
    await _emit(4)
    try:
        tex_content, tex_diff = inject_into_latex(reorder_plan, match, marked_tex, sections)
    except (KeyError, ValueError, re.error) as e:
        logger.error(f"LaTeX injection failed: {e}", exc_info=True)
        raise PipelineError(500, "LaTeX modification failed — please check your .tex format", step=4)

    # Step 5: Compile to PDF (graceful — still returns analysis if pdflatex missing)
    await _emit(5)
    pdf_url = ""
    pdf_b64 = ""
    pdf_error = ""
    filename = ""
    try:
        pdf_filename, pdf_bytes = await asyncio.to_thread(
            compile_pdf, tex_content, company_name, extracted.role_title, person_name
        )
        pdf_url = f"/output/{pdf_filename}"
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
        filename = pdf_filename.rsplit(".", 1)[0]
    except RuntimeError as e:
        pdf_error = str(e)
        logger.warning(f"PDF compilation skipped: {e}")

    elapsed_ms = int((time.time() - start) * 1000)
    logger.info(f"Tailoring complete in {elapsed_ms}ms: score={match.match_score}%")

    return TailorResponse(
        extracted=extracted,
        match=match,
        reorder_plan=reorder_plan,
        pdf_url=pdf_url,
        pdf_b64=pdf_b64,
        pdf_error=pdf_error,
        tex_content=tex_content,
        tex_diff=tex_diff,
        filename=filename,
        processing_time_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/tailor", response_model=TailorResponse)
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE}/minute")
@observe(name="resume-tailor")
async def tailor_resume(
    request: Request,
    jd_text: str = Form(..., min_length=50),
    job_title: str = Form(default=""),
    company_name: str = Form(default=""),
    user_instructions: str = Form(default=""),
    resume_file: UploadFile = File(...),
):
    """JSON endpoint: .tex file + JD text in -> tailored PDF out."""
    raw_tex = await _validate_upload(resume_file)
    logger.info(f"Tailoring resume for: {company_name or 'unknown'} / {job_title or 'unknown'}")

    try:
        result = await _execute_pipeline(raw_tex, jd_text, job_title, company_name, user_instructions)
    except PipelineError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    flush()
    return result


@router.post("/tailor-stream")
@limiter.limit(f"{RATE_LIMIT_PER_MINUTE}/minute")
@observe(name="resume-tailor-stream")
async def tailor_resume_stream(
    request: Request,
    jd_text: str = Form(..., min_length=50),
    job_title: str = Form(default=""),
    company_name: str = Form(default=""),
    user_instructions: str = Form(default=""),
    resume_file: UploadFile = File(...),
):
    """SSE streaming endpoint: same inputs, real-time progress events."""
    raw_tex = await _validate_upload(resume_file)
    logger.info(f"[stream] Tailoring resume for: {company_name or 'unknown'} / {job_title or 'unknown'}")

    async def event_generator():
        queue: asyncio.Queue[str | None] = asyncio.Queue()

        async def on_step(index: int, label: str) -> None:
            await queue.put(_sse_event("progress", {"step": index, "label": label}))

        async def run_pipeline() -> None:
            try:
                result = await _execute_pipeline(
                    raw_tex, jd_text, job_title, company_name,
                    user_instructions, on_step=on_step,
                )
                await queue.put(_sse_event("complete", result.model_dump()))
            except PipelineError as e:
                await queue.put(_sse_event("error", {"detail": e.detail, "step": e.step}))
            except Exception as e:
                logger.error(f"Unexpected pipeline error: {e}", exc_info=True)
                await queue.put(_sse_event("error", {"detail": "Internal server error", "step": -1}))
            finally:
                flush()
                await queue.put(None)  # sentinel — stop the generator

        task = asyncio.create_task(run_pipeline())

        try:
            while True:
                if await request.is_disconnected():
                    task.cancel()
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                if event is None:
                    break
                yield event
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
