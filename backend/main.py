"""Thin launcher so `uvicorn backend.main:app` works from the repo root."""
from .app.main import app, create_app  # noqa: F401

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
