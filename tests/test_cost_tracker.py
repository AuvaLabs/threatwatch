import pytest
from unittest.mock import MagicMock, patch
from modules.cost_tracker import (
    _calculate_cost,
    PRICE_CACHE_READ_PER_MTOK,
    PRICE_CACHE_WRITE_PER_MTOK,
    PRICE_INPUT_PER_MTOK,
    PRICE_OUTPUT_PER_MTOK,
    can_use_provider,
    record_provider_usage,
)


def _make_usage(input_tokens=0, output_tokens=0, cache_read=0, cache_creation=0):
    usage = MagicMock()
    usage.input_tokens = input_tokens
    usage.output_tokens = output_tokens
    usage.cache_read_input_tokens = cache_read
    usage.cache_creation_input_tokens = cache_creation
    return usage


class TestCalculateCost:
    def test_zero_usage_costs_nothing(self):
        cost, *_ = _calculate_cost(_make_usage())
        assert cost == 0.0

    def test_input_tokens_priced_per_million(self):
        cost, inp, out, cache_r, cache_w = _calculate_cost(_make_usage(input_tokens=1_000_000))
        assert abs(cost - PRICE_INPUT_PER_MTOK) < 1e-9
        assert inp == 1_000_000
        assert out == 0

    def test_output_tokens_priced_per_million(self):
        cost, *_ = _calculate_cost(_make_usage(output_tokens=1_000_000))
        assert abs(cost - PRICE_OUTPUT_PER_MTOK) < 1e-9

    def test_cache_read_cheaper_than_full_input(self):
        cost_cached, *_ = _calculate_cost(
            _make_usage(input_tokens=1_000_000, cache_read=1_000_000)
        )
        cost_normal, *_ = _calculate_cost(_make_usage(input_tokens=1_000_000))
        assert cost_cached < cost_normal

    def test_cache_read_priced_correctly(self):
        # 1M cache_read tokens, zero non-cached input
        usage = _make_usage(input_tokens=1_000_000, cache_read=1_000_000)
        cost, *_ = _calculate_cost(usage)
        # non_cached = 1M - 1M = 0; only cache_read priced
        assert abs(cost - PRICE_CACHE_READ_PER_MTOK) < 1e-9

    def test_cache_creation_priced_correctly(self):
        usage = _make_usage(input_tokens=1_000_000, cache_creation=1_000_000)
        cost, *_ = _calculate_cost(usage)
        # non_cached = 1M - 1M = 0; only cache_creation priced
        assert abs(cost - PRICE_CACHE_WRITE_PER_MTOK) < 1e-9

    def test_mixed_tokens_returns_positive_cost(self):
        usage = _make_usage(
            input_tokens=100_000,
            output_tokens=50_000,
            cache_read=10_000,
            cache_creation=5_000,
        )
        cost, inp, out, cache_r, cache_w = _calculate_cost(usage)
        assert cost > 0
        assert inp == 100_000
        assert out == 50_000
        assert cache_r == 10_000
        assert cache_w == 5_000

    def test_output_more_expensive_than_input(self):
        cost_in, *_ = _calculate_cost(_make_usage(input_tokens=1_000_000))
        cost_out, *_ = _calculate_cost(_make_usage(output_tokens=1_000_000))
        assert cost_out > cost_in

    def test_usage_without_cache_attributes(self):
        usage = MagicMock(spec=["input_tokens", "output_tokens"])
        usage.input_tokens = 500
        usage.output_tokens = 100
        cost, *_ = _calculate_cost(usage)
        assert cost >= 0


class TestCheckDailyBudget:
    def test_budget_ok_when_no_spend(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.cost_tracker.COST_FILE", tmp_path / "costs.json")
        from modules.cost_tracker import check_daily_budget
        assert check_daily_budget() is True

    def test_budget_exceeded_when_over_limit(self, tmp_path, monkeypatch):
        import json
        from datetime import datetime, timezone
        monkeypatch.setattr("modules.cost_tracker.COST_FILE", tmp_path / "costs.json")
        monkeypatch.setattr("modules.cost_tracker.DAILY_BUDGET_USD", 1.00)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        data = {"daily": {today: {"cost_usd": 2.00}}, "total_usd": 2.00}
        (tmp_path / "costs.json").write_text(json.dumps(data))

        from modules.cost_tracker import check_daily_budget
        assert check_daily_budget() is False


class TestProviderAccounting:
    def test_null_state_is_repaired_at_the_persistence_boundary(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.cost_tracker.COST_FILE", tmp_path / "costs.json")
        (tmp_path / "costs.json").write_text(
            '{"daily":null,"total_usd":null}', encoding="utf-8"
        )

        cost = record_provider_usage(
            "anthropic",
            "claude-haiku-5-5",
            {"usage": {"prompt_tokens": 10, "completion_tokens": 5}},
        )

        assert cost > 0
        data = __import__("json").loads((tmp_path / "costs.json").read_text())
        assert data["total_usd"] > 0
        assert next(iter(data["daily"].values()))["api_calls"] == 1

    def test_anthropic_usage_updates_enforced_cost_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.cost_tracker.COST_FILE", tmp_path / "costs.json")
        cost = record_provider_usage(
            "anthropic",
            "claude-haiku-5-5",
            {"usage": {"prompt_tokens": 100_000, "completion_tokens": 100_000}},
            caller="summaries",
        )

        assert cost == pytest.approx(0.06)
        data = __import__("json").loads((tmp_path / "costs.json").read_text())
        day = next(iter(data["daily"].values()))
        assert day["api_calls"] == 1
        assert day["by_provider"]["anthropic"]["cost_usd"] == pytest.approx(0.06)

    def test_zero_cost_provider_remains_available_after_paid_budget(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.cost_tracker.COST_FILE", tmp_path / "costs.json")
        monkeypatch.setattr("modules.cost_tracker.DAILY_BUDGET_USD", 0.01)
        monkeypatch.setenv("LLM_ZERO_COST_PROVIDERS", "primary,fallback")
        record_provider_usage(
            "anthropic",
            "claude-sonnet-5-5",
            {"usage": {"prompt_tokens": 10_000, "completion_tokens": 1_000}},
        )

        assert can_use_provider("anthropic") is False
        assert can_use_provider("primary") is True
