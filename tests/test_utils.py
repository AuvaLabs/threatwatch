"""Tests for modules/utils.py — time slugs and path helpers."""
import re
from pathlib import Path
from unittest.mock import patch

from modules.utils import (
    get_current_hour_slug,
    get_month_slug,
    get_today_slug,
    get_week_slug,
    get_year_slug,
    make_output_path,
)


class TestTimeSlugs:
    def test_hour_slug_format(self):
        slug = get_current_hour_slug()
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{2}", slug), f"Unexpected format: {slug}"

    def test_today_slug_format(self):
        slug = get_today_slug()
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", slug), f"Unexpected format: {slug}"

    def test_week_slug_format(self):
        slug = get_week_slug()
        assert re.fullmatch(r"\d{4}-W\d{2}", slug), f"Unexpected format: {slug}"

    def test_month_slug_format(self):
        slug = get_month_slug()
        assert re.fullmatch(r"\d{4}-\d{2}", slug), f"Unexpected format: {slug}"

    def test_year_slug_format(self):
        slug = get_year_slug()
        assert re.fullmatch(r"\d{4}", slug), f"Unexpected format: {slug}"

    def test_slugs_are_utc_consistent(self):
        # All slugs for a given moment should start with the same year
        year = get_year_slug()
        month = get_month_slug()
        today = get_today_slug()
        assert month.startswith(year)
        assert today.startswith(month)


class TestMakeOutputPath:
    def test_returns_path_with_slug(self, tmp_path):
        with patch("modules.utils.Path", side_effect=lambda *a: tmp_path.joinpath(*a)):
            # Directly call with known inputs
            pass
        # Call real function and check filename
        result = make_output_path("daily", "2026-03-15")
        assert result.name == "2026-03-15.json"
        assert "daily" in str(result)
