import os

from dotenv import load_dotenv

load_dotenv()


API_URL: str = os.getenv("API_URL", "http://app:5000/cve/batch-upload")
REPO_URL: str = os.getenv("REPO_URL", "https://github.com/CVEProject/cvelistV5")
FETCH_INTERVAL_HOURS: int = os.getenv("FETCH_INTERVAL_HOURS", 6)

