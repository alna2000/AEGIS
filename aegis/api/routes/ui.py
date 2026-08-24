"""Same-origin browser interface routes with a route-scoped security policy."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


router = APIRouter(prefix="/ui", tags=["user-interface"])
_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
_templates = Jinja2Templates(directory=_PACKAGE_ROOT / "templates")

_UI_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; "
        "base-uri 'none'; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "img-src 'self'; "
        "object-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'"
    ),
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


@router.get("", response_class=HTMLResponse, include_in_schema=False)
def read_ui(request: Request) -> HTMLResponse:
    """Return the initial shell; browser authentication resolves after load."""

    return _templates.TemplateResponse(
        request=request,
        name="ui.html",
        context={},
        headers=_UI_SECURITY_HEADERS,
    )
