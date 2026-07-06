# Contributing

Thanks for improving ObscuraPrimus.

## Development Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest discover -s tests
python app.py
```

## Pull Request Checklist

- Keep dependencies minimal.
- Add or update tests for steganography or crypto behavior changes.
- Run `python -m unittest discover -s tests`.
- Run `python -m compileall app.py obscuraprimus`.
- For release changes, run `powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1 -Version 1.0.0`.
- Avoid committing `build/`, `dist/`, `release/`, or local cover/secret files.
