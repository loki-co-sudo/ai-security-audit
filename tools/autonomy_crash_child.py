"""強制終了(プロセスkill相当)を再現する試験用の子プロセス。tools/test_fuzz_resume.py から起動される。

指定した位置で os._exit(137) し、finally や後始末を一切走らせない(本物のクラッシュと同じ)。
  crash 指定: "<journal|store>:<名前>:<task_id>:<before|after>"
    journal:action_started:fuzz:after      … journalのaction_started(fuzz)を書いた直後
    store:finish_task:fuzz:before          … 実行後、状態ストアへcommitする直前
    store:finish_task:fuzz:after           … commit直後・journalのaction_finished前
引数は JSON(1つ): {"target","journal_root","crash","run": {...AutonomousFuzzAgent.run のkwargs},
                  "grants": [{"capability","args","ttl"}], "config": {...}}
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def install_crash(spec: str) -> None:
    kind, name, task, when = spec.split(":")

    def wrap(orig, matches):
        def f(*a, **kw):
            hit = matches(a, kw)
            if hit and when == "before":
                os._exit(137)
            r = orig(*a, **kw)
            if hit and when == "after":
                os._exit(137)
            return r
        return f

    if kind == "journal":
        from core.autonomy.journal import RunJournal
        RunJournal.append = wrap(RunJournal.append, lambda a, kw: a[1] == name and kw.get("task_id") == task)
    else:
        from core.autonomy.run_store import RunStore
        orig = getattr(RunStore, name)
        setattr(RunStore, name, wrap(orig, lambda a, kw: (a[1] if len(a) > 1 else kw.get("task_id")) == task))


def main() -> int:
    cfg = json.loads(sys.argv[1])
    if cfg.get("crash"):
        install_crash(cfg["crash"])
    from agents.fuzz_agent import FuzzAgent
    from agents.fuzz_capabilities import AutonomousFuzzAgent
    from core import config as _config
    from core.autonomy.actions import new_grant
    from core.event_bus import EventBus
    from tools.fuzz_characterization import MockLLM

    _config._cfg.clear()
    _config._cfg.update({**_config._DEFAULTS, **cfg.get("config", {})})
    FuzzAgent._save_investigation = lambda *a, **k: None
    FuzzAgent._record_telemetry = lambda *a, **k: None
    agent = AutonomousFuzzAgent(EventBus(), MockLLM())
    agent.set_effort_override("speed")
    grants = [new_grant(g["capability"], g["args"], expires_at=time.time() + g.get("ttl", 600),
                        grant_id=g.get("grant_id")) for g in cfg.get("grants", [])]
    kw = dict(cfg["run"])
    agent._safe_run(target=cfg["target"], journal_root=cfg["journal_root"], approvals=grants, **kw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
