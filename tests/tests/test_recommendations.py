"""Tests for the recommendations module."""
import pytest

from scanner.output.recommendations import (
    RECOMMENDATIONS,
    Recommendation,
    generate_recommendations_report,
    get_recommendation,
)
from scanner.core.analysis import Finding


def _make_finding(secret_type: str = "Generic Secret", severity: str = "HIGH", **kw) -> Finding:
    defaults = dict(
        file="test.py",
        line_number=1,
        line_content="secret = 'value'",
        matched_value="some_secret_value",
        score=10,
        category="credential",
        source="current",
        entropy=4.5,
        context_match=True,
        structural_valid=False,
        confidence=0.85,
        taint_traces=[],
    )
    defaults.update(kw)
    defaults["secret_type"] = secret_type
    defaults["severity"] = severity
    return Finding(**defaults)


# ── get_recommendation ────────────────────────────────────────────────────────

class TestGetRecommendation:
    def test_returns_recommendation_for_known_type(self):
        rec = get_recommendation("AWS Access Key")
        assert isinstance(rec, Recommendation)
        assert rec.priority == "high"

    def test_returns_default_for_unknown_type(self):
        rec = get_recommendation("Unknown Secret Type 12345")
        assert isinstance(rec, Recommendation)
        assert rec == RECOMMENDATIONS["default"]

    def test_aws_access_key_has_code_example(self):
        rec = get_recommendation("AWS Access Key")
        assert rec.code_example is not None
        assert "os.getenv" in rec.code_example

    def test_github_token_has_code_example(self):
        rec = get_recommendation("GitHub Token")
        assert rec.code_example is not None
        assert "GITHUB_TOKEN" in rec.code_example

    def test_connection_string_has_code_example(self):
        rec = get_recommendation("Connection String")
        assert rec.code_example is not None
        assert "DATABASE_URL" in rec.code_example

    def test_private_key_is_high_priority(self):
        rec = get_recommendation("Private Key")
        assert rec.priority == "high"

    def test_jwt_token_is_medium_priority(self):
        rec = get_recommendation("JWT Token")
        assert rec.priority == "medium"

    def test_all_recommendations_have_title_and_description(self):
        for name, rec in RECOMMENDATIONS.items():
            assert rec.title, f"Recommendation '{name}' missing title"
            assert rec.description, f"Recommendation '{name}' missing description"

    def test_all_recommendations_have_valid_priority(self):
        valid_priorities = {"high", "medium", "low"}
        for name, rec in RECOMMENDATIONS.items():
            assert rec.priority in valid_priorities, f"'{name}' has invalid priority: {rec.priority}"

    @pytest.mark.parametrize("secret_type", [
        "AWS Access Key", "AWS Secret Key", "GitHub Token",
        "Stripe Secret Key", "Private Key", "JWT Token",
        "Connection String", "Generic Secret", "Generic API Key",
        "Bearer Token", "Basic Auth", "Telegram Bot Token",
        "Google API Key", "Generic Token", "SendGrid API Key",
    ])
    def test_known_types_have_dedicated_recommendations(self, secret_type):
        rec = get_recommendation(secret_type)
        assert rec != RECOMMENDATIONS["default"], f"'{secret_type}' falls back to default"


# ── generate_recommendations_report ───────────────────────────────────────────

class TestGenerateRecommendationsReport:
    def test_empty_findings_returns_clean_message(self):
        report = generate_recommendations_report([])
        assert "Утечек не найдено" in report

    def test_report_contains_section_header(self):
        findings = [_make_finding("AWS Access Key", "CRITICAL")]
        report = generate_recommendations_report(findings)
        assert "РЕКОМЕНДАЦИИ ПО УСТРАНЕНИЮ УТЕЧЕК" in report

    def test_report_contains_secret_type(self):
        findings = [_make_finding("AWS Access Key", "CRITICAL")]
        report = generate_recommendations_report(findings)
        assert "AWS Access Key" in report

    def test_report_contains_count(self):
        findings = [
            _make_finding("AWS Access Key", "CRITICAL"),
            _make_finding("AWS Access Key", "CRITICAL", line_number=5),
        ]
        report = generate_recommendations_report(findings)
        assert "2 утечек" in report

    def test_report_contains_priority_emoji(self):
        findings = [_make_finding("AWS Access Key", "CRITICAL")]
        report = generate_recommendations_report(findings)
        assert "🔴" in report

    def test_report_contains_medium_priority_emoji(self):
        findings = [_make_finding("JWT Token", "MEDIUM")]
        report = generate_recommendations_report(findings)
        assert "🟡" in report

    def test_report_contains_general_recommendations(self):
        findings = [_make_finding()]
        report = generate_recommendations_report(findings)
        assert "ОБЩИЕ РЕКОМЕНДАЦИИ" in report
        assert "HashiCorp Vault" in report
        assert "pre-commit" in report

    def test_report_contains_code_example_if_available(self):
        findings = [_make_finding("AWS Access Key", "CRITICAL")]
        report = generate_recommendations_report(findings)
        assert "os.getenv" in report

    def test_report_sorted_by_priority(self):
        findings = [
            _make_finding("JWT Token", "MEDIUM"),
            _make_finding("AWS Access Key", "CRITICAL"),
        ]
        report = generate_recommendations_report(findings)
        # high priority (AWS) should appear before medium (JWT)
        aws_pos = report.index("AWS Access Key")
        jwt_pos = report.index("JWT Token")
        assert aws_pos < jwt_pos

    def test_multiple_types_grouped(self):
        findings = [
            _make_finding("AWS Access Key", "CRITICAL"),
            _make_finding("AWS Access Key", "CRITICAL", line_number=10),
            _make_finding("GitHub Token", "HIGH"),
        ]
        report = generate_recommendations_report(findings)
        assert "AWS Access Key" in report
        assert "GitHub Token" in report
        assert "2 утечек" in report

    def test_report_is_string(self):
        findings = [_make_finding()]
        report = generate_recommendations_report(findings)
        assert isinstance(report, str)
        assert len(report) > 100


# ── Recommendation dataclass ──────────────────────────────────────────────────

class TestRecommendationDataclass:
    def test_default_priority(self):
        rec = Recommendation(title="Test", description="Test desc")
        assert rec.priority == "high"
        assert rec.code_example is None

    def test_with_code_example(self):
        rec = Recommendation(
            title="Test",
            description="Test desc",
            code_example="x = 1",
            priority="low",
        )
        assert rec.code_example == "x = 1"
        assert rec.priority == "low"


# ── RECOMMENDATIONS dict integrity ───────────────────────────────────────────

class TestRecommendationsDict:
    def test_has_default_entry(self):
        assert "default" in RECOMMENDATIONS

    def test_minimum_number_of_entries(self):
        assert len(RECOMMENDATIONS) >= 15

    def test_all_values_are_recommendation_instances(self):
        for key, value in RECOMMENDATIONS.items():
            assert isinstance(value, Recommendation), f"Key '{key}' is not a Recommendation"
