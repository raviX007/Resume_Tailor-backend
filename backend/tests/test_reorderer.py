"""Comprehensive tests for app.services.reorderer.compute_reorder_plan.

Covers:
- skills_category_order sorting by match count descending
- project_order sorting by keyword overlap
- summary_first_line with explicit role_title and fallback via CATEGORY_ROLE_MAP
- experience_emphasis keyword extraction per entry
- edge cases: empty sections, no matches, missing keys
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app.models import ExtractedKeywords, MatchResult, ReorderPlan
from app.services.reorderer import CATEGORY_ROLE_MAP, compute_reorder_plan


# ---------------------------------------------------------------------------
# Helpers — factory functions for building model instances with sane defaults
# ---------------------------------------------------------------------------

def _extracted(**overrides) -> ExtractedKeywords:
    """Build an ExtractedKeywords with optional field overrides."""
    defaults = dict(
        languages=["Python", "Java"],
        backend=["Django", "FastAPI"],
        frontend=["React"],
        ai_llm=["LangChain"],
        databases=["PostgreSQL"],
        devops=["Docker"],
        soft_skills=[],
        domains=[],
        role_title="",
        experience_level="mid",
    )
    defaults.update(overrides)
    return ExtractedKeywords(**defaults)


def _match(**overrides) -> MatchResult:
    """Build a MatchResult with optional field overrides."""
    defaults = dict(
        matched={"backend": ["Django", "FastAPI"], "languages": ["Python"]},
        missing_from_resume={"frontend": ["React"]},
        injectable={"databases": ["PostgreSQL"]},
        total_jd_keywords=10,
        total_matched=3,
        match_score=30,
        dominant_category="backend",
    )
    defaults.update(overrides)
    return MatchResult(**defaults)


def _sections(**overrides) -> dict:
    """Build a sections dict with optional key overrides."""
    defaults = dict(
        skills={
            "backend": ["Django", "FastAPI", "Flask"],
            "languages": ["Python", "Java", "Go"],
            "frontend": ["React", "Vue"],
            "databases": ["PostgreSQL", "Redis"],
        },
        projects={
            "ChatBot": "Built a chatbot using Django and LangChain with Python.",
            "Portfolio": "Personal portfolio site built with React and Vue.",
            "DataPipeline": "ETL pipeline using PostgreSQL and Docker.",
        },
        experience={
            "Acme Corp": "Developed Django and FastAPI microservices in Python.",
            "Beta Inc": "Built React dashboards and maintained PostgreSQL databases.",
        },
    )
    defaults.update(overrides)
    return defaults


# ===========================================================================
# 1. skills_category_order — sorted by match count descending
# ===========================================================================

class TestSkillsCategoryOrder:
    """Skills categories should be ordered by how many matches they have."""

    def test_basic_ordering_by_match_count(self):
        """Category with more matches appears before one with fewer."""
        match = _match(matched={
            "backend": ["Django", "FastAPI", "Flask"],   # 3
            "languages": ["Python"],                      # 1
            "frontend": ["React", "Vue"],                 # 2
            "databases": [],                              # 0
        })
        sections = _sections()
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert plan.skills_category_order == ["backend", "frontend", "languages", "databases"]

    def test_tied_counts_preserves_all_categories(self):
        """When counts are tied, all categories still appear in the output."""
        match = _match(matched={
            "backend": ["Django"],
            "languages": ["Python"],
            "frontend": ["React"],
            "databases": ["PostgreSQL"],
        })
        sections = _sections()
        plan = compute_reorder_plan(_extracted(), match, sections)

        # All four categories must be present regardless of tie order
        assert set(plan.skills_category_order) == {"backend", "languages", "frontend", "databases"}
        assert len(plan.skills_category_order) == 4

    def test_unmatched_categories_appear_last(self):
        """Categories with zero matches should be at the end."""
        match = _match(matched={
            "backend": ["Django"],
        })
        sections = _sections(skills={
            "backend": ["Django"],
            "languages": ["Python"],
            "frontend": ["React"],
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert plan.skills_category_order[0] == "backend"
        # languages and frontend have 0 matches — they come after backend
        assert "languages" in plan.skills_category_order
        assert "frontend" in plan.skills_category_order

    def test_only_section_categories_used(self):
        """Categories not present in sections["skills"] should NOT appear."""
        match = _match(matched={
            "backend": ["Django"],
            "ai_llm": ["LangChain"],  # ai_llm not in sections skills
        })
        sections = _sections(skills={
            "backend": ["Django", "FastAPI"],
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert plan.skills_category_order == ["backend"]
        assert "ai_llm" not in plan.skills_category_order

    def test_single_category(self):
        """Works correctly when there is only one skills category."""
        match = _match(matched={"languages": ["Python", "Go"]})
        sections = _sections(skills={"languages": ["Python", "Go", "Java"]})
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert plan.skills_category_order == ["languages"]


# ===========================================================================
# 2. project_order — sorted by keyword overlap with matched keywords
# ===========================================================================

class TestProjectOrder:
    """Projects should be ordered by overlap with all matched keywords."""

    def test_project_with_more_keyword_hits_ranks_first(self):
        """A project mentioning more matched keywords ranks higher."""
        match = _match(matched={
            "backend": ["Django", "FastAPI"],
            "languages": ["Python"],
        })
        sections = _sections(projects={
            "ProjectA": "Uses Django, FastAPI, and Python together.",   # 3 hits
            "ProjectB": "Uses Django only.",                            # 1 hit
            "ProjectC": "Uses Python and FastAPI for the API layer.",   # 2 hits
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert plan.project_order[0] == "ProjectA"
        assert plan.project_order[1] == "ProjectC"
        assert plan.project_order[2] == "ProjectB"

    def test_case_insensitive_keyword_matching(self):
        """Keyword matching in project content should be case-insensitive."""
        match = _match(matched={"backend": ["Django"]})
        sections = _sections(projects={
            "Upper": "Built with DJANGO framework.",
            "Lower": "Built with django framework.",
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        # Both should match; order between ties is stable but both present
        assert set(plan.project_order) == {"Upper", "Lower"}

    def test_project_with_zero_overlap_still_included(self):
        """Projects that match no keywords should still be in the list."""
        match = _match(matched={"backend": ["Django"]})
        sections = _sections(projects={
            "Relevant": "Built with Django.",
            "Unrelated": "No matching keywords here.",
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert plan.project_order[0] == "Relevant"
        assert "Unrelated" in plan.project_order

    def test_no_projects_section(self):
        """When there are no projects at all, project_order is empty."""
        match = _match()
        sections = _sections(projects={})
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert plan.project_order == []

    def test_keywords_from_multiple_categories(self):
        """Overlap scoring considers keywords from ALL matched categories."""
        match = _match(matched={
            "backend": ["Django"],
            "databases": ["PostgreSQL"],
            "devops": ["Docker"],
        })
        sections = _sections(projects={
            "AllThree": "Django with PostgreSQL and Docker.",   # 3 hits
            "TwoHits": "Django and PostgreSQL setup.",          # 2 hits
            "OneHit": "Only Docker.",                           # 1 hit
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert plan.project_order == ["AllThree", "TwoHits", "OneHit"]


# ===========================================================================
# 3. summary_first_line — role_title with/without fallback
# ===========================================================================

class TestSummaryFirstLine:
    """summary_first_line should use role_title when available, else the map."""

    def test_uses_explicit_role_title(self):
        """When extracted.role_title is set, it appears in the summary line."""
        extracted = _extracted(role_title="Senior Backend Engineer")
        match = _match(matched={"backend": ["Django", "FastAPI"]})
        sections = _sections()
        plan = compute_reorder_plan(extracted, match, sections)

        assert plan.summary_first_line.startswith("Senior Backend Engineer")

    def test_fallback_to_category_role_map(self):
        """When role_title is empty, dominant_category drives the role via the map."""
        extracted = _extracted(role_title="")
        match = _match(
            dominant_category="ai_llm",
            matched={"ai_llm": ["LangChain", "OpenAI"]},
        )
        sections = _sections(skills={"ai_llm": ["LangChain", "OpenAI"]})
        plan = compute_reorder_plan(extracted, match, sections)

        assert "AI/LLM Engineer" in plan.summary_first_line

    def test_fallback_default_software_developer(self):
        """When dominant_category is not in the map, defaults to 'Software Developer'."""
        extracted = _extracted(role_title="")
        match = _match(
            dominant_category="soft_skills",  # not in CATEGORY_ROLE_MAP
            matched={"soft_skills": ["leadership"]},
        )
        sections = _sections(skills={"soft_skills": ["leadership"]})
        plan = compute_reorder_plan(extracted, match, sections)

        assert "Software Developer" in plan.summary_first_line

    def test_summary_includes_top_skills(self):
        """Summary line should mention top matched skills after the role title."""
        extracted = _extracted(role_title="Backend Developer")
        match = _match(matched={
            "backend": ["Django", "FastAPI"],
            "languages": ["Python"],
        })
        sections = _sections()
        plan = compute_reorder_plan(extracted, match, sections)

        assert "Django" in plan.summary_first_line
        assert "hands-on expertise" in plan.summary_first_line

    def test_summary_no_matches_no_skills_mention(self):
        """When there are no matched skills, summary is just 'RoleTitle.'."""
        extracted = _extracted(role_title="Data Engineer")
        match = _match(matched={})
        sections = _sections(skills={})
        plan = compute_reorder_plan(extracted, match, sections)

        assert plan.summary_first_line == "Data Engineer."

    def test_summary_limits_skills_to_three_in_mention(self):
        """The skills_mention in the summary should list at most 3 skills."""
        extracted = _extracted(role_title="Developer")
        match = _match(matched={
            "backend": ["Django", "FastAPI"],
            "languages": ["Python", "Go"],
            "databases": ["PostgreSQL", "Redis"],
        })
        sections = _sections(skills={
            "backend": ["Django", "FastAPI"],
            "languages": ["Python", "Go"],
            "databases": ["PostgreSQL", "Redis"],
        })
        plan = compute_reorder_plan(extracted, match, sections)

        # The format is: "RoleTitle with hands-on expertise in A, B, C."
        # Count the items between "in " and the final "."
        assert plan.summary_first_line.count(",") <= 2  # at most 3 items => at most 2 commas

    @pytest.mark.parametrize("dominant,expected_role", [
        ("ai_llm", "AI/LLM Engineer"),
        ("backend", "Backend Developer"),
        ("frontend", "Frontend Developer"),
        ("languages", "Software Developer"),
        ("databases", "Software Developer"),
        ("devops", "DevOps Engineer"),
        ("domains", "Software Developer"),
    ])
    def test_category_role_map_values(self, dominant, expected_role):
        """Each dominant_category maps to the correct fallback role title."""
        extracted = _extracted(role_title="")
        match = _match(
            dominant_category=dominant,
            matched={dominant: ["SomeSkill"]},
        )
        sections = _sections(skills={dominant: ["SomeSkill"]})
        plan = compute_reorder_plan(extracted, match, sections)

        assert expected_role in plan.summary_first_line


# ===========================================================================
# 4. experience_emphasis — matched keywords found in experience content
# ===========================================================================

class TestExperienceEmphasis:
    """experience_emphasis should list matched keywords found in each entry."""

    def test_keywords_found_in_experience_content(self):
        """Keywords present in an experience entry's content are returned."""
        match = _match(matched={
            "backend": ["Django", "FastAPI"],
            "languages": ["Python"],
        })
        sections = _sections(experience={
            "Acme Corp": "Built microservices with Django and Python.",
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        emphasis = plan.experience_emphasis["Acme Corp"]
        assert "django" in emphasis
        assert "python" in emphasis

    def test_keywords_not_in_content_excluded(self):
        """Keywords NOT in an experience entry's content should not appear."""
        match = _match(matched={
            "backend": ["Django", "FastAPI"],
        })
        sections = _sections(experience={
            "Beta Inc": "Worked on React front-end applications.",
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        emphasis = plan.experience_emphasis["Beta Inc"]
        assert "django" not in emphasis
        assert "fastapi" not in emphasis

    def test_experience_emphasis_case_insensitive(self):
        """Keyword matching in experience content is case-insensitive."""
        match = _match(matched={"backend": ["Django"]})
        sections = _sections(experience={
            "Job": "Used DJANGO for the backend.",
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert "django" in plan.experience_emphasis["Job"]

    def test_experience_emphasis_capped_at_five(self):
        """Each entry should have at most 5 emphasized keywords."""
        match = _match(matched={
            "backend": ["Django", "FastAPI", "Flask"],
            "languages": ["Python", "Go", "Rust"],
            "databases": ["PostgreSQL", "Redis"],
        })
        sections = _sections(experience={
            "MegaCorp": (
                "Built systems with Django, FastAPI, Flask, Python, Go, Rust, "
                "PostgreSQL, and Redis."
            ),
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert len(plan.experience_emphasis["MegaCorp"]) <= 5

    def test_multiple_experience_entries(self):
        """Each experience entry gets its own emphasis list."""
        match = _match(matched={
            "backend": ["Django"],
            "databases": ["PostgreSQL"],
        })
        sections = _sections(experience={
            "Company A": "Django web application.",
            "Company B": "PostgreSQL data warehouse.",
            "Company C": "No relevant keywords.",
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert "django" in plan.experience_emphasis["Company A"]
        assert "postgresql" in plan.experience_emphasis["Company B"]
        assert plan.experience_emphasis["Company C"] == []


# ===========================================================================
# 5. Edge cases
# ===========================================================================

class TestEdgeCases:
    """Edge cases: empty sections, no matches, missing keys."""

    def test_empty_sections_dict(self):
        """When sections is completely empty, plan returns empty collections."""
        plan = compute_reorder_plan(_extracted(), _match(), {})

        assert plan.skills_category_order == []
        assert plan.project_order == []
        assert plan.experience_emphasis == {}

    def test_no_matched_keywords_at_all(self):
        """When matched dict is empty, ordering still works without errors."""
        match = _match(matched={})
        sections = _sections()
        plan = compute_reorder_plan(_extracted(), match, sections)

        # All skills categories present but all with 0 matches
        assert set(plan.skills_category_order) == set(sections["skills"].keys())
        # Projects still listed (all with score 0)
        assert set(plan.project_order) == set(sections["projects"].keys())

    def test_missing_skills_key_in_sections(self):
        """When 'skills' key is absent from sections, skills_category_order is empty."""
        sections = {
            "projects": {"P1": "content"},
            "experience": {"E1": "content"},
        }
        plan = compute_reorder_plan(_extracted(), _match(), sections)

        assert plan.skills_category_order == []

    def test_missing_projects_key_in_sections(self):
        """When 'projects' key is absent from sections, project_order is empty."""
        sections = {
            "skills": {"backend": ["Django"]},
            "experience": {"E1": "content"},
        }
        plan = compute_reorder_plan(_extracted(), _match(), sections)

        assert plan.project_order == []

    def test_missing_experience_key_in_sections(self):
        """When 'experience' key is absent, experience_emphasis is empty."""
        sections = {
            "skills": {"backend": ["Django"]},
            "projects": {"P1": "Django project"},
        }
        plan = compute_reorder_plan(_extracted(), _match(), sections)

        assert plan.experience_emphasis == {}

    def test_return_type_is_reorder_plan(self):
        """The function returns a ReorderPlan Pydantic model instance."""
        plan = compute_reorder_plan(_extracted(), _match(), _sections())

        assert isinstance(plan, ReorderPlan)

    def test_empty_skills_dict_in_sections(self):
        """When skills dict exists but is empty, skills_category_order is empty."""
        sections = _sections(skills={})
        plan = compute_reorder_plan(_extracted(), _match(), sections)

        assert plan.skills_category_order == []

    def test_projects_with_empty_content(self):
        """Projects whose content is empty string should still appear in order."""
        match = _match(matched={"backend": ["Django"]})
        sections = _sections(projects={
            "EmptyProject": "",
            "RealProject": "Built with Django.",
        })
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert plan.project_order[0] == "RealProject"
        assert "EmptyProject" in plan.project_order

    def test_experience_with_empty_content(self):
        """Experience entries with empty content produce empty emphasis list."""
        match = _match(matched={"backend": ["Django"]})
        sections = _sections(experience={"GhostJob": ""})
        plan = compute_reorder_plan(_extracted(), match, sections)

        assert plan.experience_emphasis["GhostJob"] == []


# ===========================================================================
# 6. CATEGORY_ROLE_MAP integrity
# ===========================================================================

class TestCategoryRoleMap:
    """Validate the CATEGORY_ROLE_MAP constant itself."""

    def test_map_contains_expected_keys(self):
        expected_keys = {"ai_llm", "backend", "frontend", "languages", "databases", "devops", "domains"}
        assert set(CATEGORY_ROLE_MAP.keys()) == expected_keys

    def test_all_values_are_non_empty_strings(self):
        for key, value in CATEGORY_ROLE_MAP.items():
            assert isinstance(value, str), f"Value for {key} is not a string"
            assert len(value) > 0, f"Value for {key} is empty"
