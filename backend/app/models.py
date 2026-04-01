"""Pydantic request/response models for the resume-tailor API."""

from typing import TypedDict

from pydantic import BaseModel, Field


class ResumeSections(TypedDict):
    """Parsed .tex resume sections returned by parser.parse_resume_sections."""
    summary: str
    skills: dict[str, str]
    experience: dict[str, str]
    projects: dict[str, str]


class TailorRequest(BaseModel):
    """Input from UI or pipeline integration."""
    jd_text: str = Field(..., min_length=50, description="Full job description text")
    job_title: str = Field(default="", description="Job title (optional, extracted from JD if empty)")
    company_name: str = Field(default="", description="Company name (optional)")
    job_id: int | None = Field(default=None, description="Job ID from pipeline DB (for integration)")


class ExtractedKeywords(BaseModel):
    """Output of Step 1: LLM extraction from JD."""
    languages: list[str] = []
    backend: list[str] = []
    frontend: list[str] = []
    ai_llm: list[str] = []
    databases: list[str] = []
    devops: list[str] = []
    soft_skills: list[str] = []
    domains: list[str] = []
    role_title: str = ""
    experience_level: str = ""


class MatchResult(BaseModel):
    """Output of Step 2: Match against master_skills."""
    matched: dict[str, list[str]]
    missing_from_resume: dict[str, list[str]]
    injectable: dict[str, list[str]]
    total_jd_keywords: int
    total_matched: int
    match_score: int
    dominant_category: str


class ReorderPlan(BaseModel):
    """Output of Step 3: How to reorder the resume."""
    skills_category_order: list[str]
    project_order: list[str]
    summary_first_line: str
    experience_emphasis: dict[str, list[str]]


class ResumeAnalysis(BaseModel):
    """Output of Step 0: LLM analysis of uploaded .tex file."""
    marked_tex: str = Field(..., description="The .tex content with comment markers inserted")
    skills: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Extracted skills by category (replaces master_skills.yaml)",
    )
    sections_found: list[str] = Field(
        default_factory=list,
        description="Which sections were identified: summary, skills, experience, projects",
    )
    person_name: str = Field(default="", description="Name extracted from the resume header")


class TailorResponse(BaseModel):
    """Full response to the UI."""
    extracted: ExtractedKeywords
    match: MatchResult
    reorder_plan: ReorderPlan
    pdf_url: str
    pdf_b64: str = ""
    pdf_error: str = ""
    tex_content: str = ""
    tex_diff: str
    filename: str = ""
    processing_time_ms: int
