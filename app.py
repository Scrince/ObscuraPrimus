from obscuraprimus.advanced_analysis import maybe_run_analyze_worker
from obscuraprimus.forensics import maybe_run_forensic_worker
from obscuraprimus.gui_main import main

if __name__ == "__main__":
    if maybe_run_analyze_worker() or maybe_run_forensic_worker():
        raise SystemExit(0)
    main()
