import os
from unittest.mock import patch

from scripts import run_pipeline


def test_routine_llm_runs_initially_then_every_third_pipeline_tick():
    assert run_pipeline._routine_llm_env(0, every=3) == {
        "ROUTINE_LLM_ENABLED": "1",
    }
    assert run_pipeline._routine_llm_env(1, every=3) == {
        "ROUTINE_LLM_ENABLED": "1",
    }
    assert run_pipeline._routine_llm_env(2, every=3) == {
        "ROUTINE_LLM_ENABLED": "0",
    }
    assert run_pipeline._routine_llm_env(3, every=3) == {
        "ROUTINE_LLM_ENABLED": "0",
    }
    assert run_pipeline._routine_llm_env(4, every=3) == {
        "ROUTINE_LLM_ENABLED": "1",
    }


def test_run_passes_scoped_environment_overrides():
    with patch("scripts.run_pipeline.subprocess.run") as run:
        run.return_value.returncode = 0
        run_pipeline._run(
            "threatdigest_main.py", {"ROUTINE_LLM_ENABLED": "0"},
        )

    child_env = run.call_args.kwargs["env"]
    assert child_env["ROUTINE_LLM_ENABLED"] == "0"
    assert child_env["PATH"] == os.environ["PATH"]


def test_zero_cadence_disables_routine_llm():
    assert run_pipeline._routine_llm_env(0, every=0) == {
        "ROUTINE_LLM_ENABLED": "0",
    }
