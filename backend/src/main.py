import uvicorn

from dotenv import load_dotenv
from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi_pagination import add_pagination

from src.config import DEBUG
from src.cve_app.routers import cve_app


load_dotenv()


def create_app():
    fast_api_app = FastAPI(
        debug=bool(DEBUG),
        docs_url="/api/docs/",
    )

    fast_api_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    add_pagination(fast_api_app)

    return fast_api_app


fastapi_app = create_app()

main_api_router = APIRouter()
fastapi_app.include_router(cve_app, prefix="", tags=["CVE Service"])
fastapi_app.include_router(main_api_router)


if __name__ == "__main__":
    uvicorn.run(fastapi_app, host="0.0.0.0", port=5000)
