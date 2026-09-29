import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from scanner.api import router as api_router
from scanner.config import load_roles
from scanner.errors import ScannerError
from scanner.logging_setup import configure_logging, get_logger, log_event
from scanner.policy.roles import RoleAuthorizer
from scanner.service import ScannerService

configure_logging()
logger = get_logger("http")

app = FastAPI(title="Supply Chain Policy Scanner", version="1.0.0")
app.state.authorizer = RoleAuthorizer(load_roles())
app.state.service = ScannerService(authorizer=app.state.authorizer)

app.include_router(api_router)


@app.exception_handler(ScannerError)
async def scanner_error_handler(request: Request, exc: ScannerError) -> JSONResponse:
    log_event(
        logger, "request_error",
        path=request.url.path, code=exc.code, detail=exc.message,
        error_details=exc.details,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message,
                           "details": exc.details}},
    )


@app.get("/")
def read_root():
    return {"Hello": "World"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
