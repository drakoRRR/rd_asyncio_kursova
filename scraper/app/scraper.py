from datetime import datetime
import aiohttp
import asyncio
import aiofiles
import json
import os
from git import Repo
import logging
import sys
from app.config import API_URL, REPO_URL, FETCH_INTERVAL_HOURS

LOCAL_PATH = "cve/jsons"
CVE_FOLDER = "cves"
MAX_CONCURRENT_FILES = 50

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BATCH_UPLOAD_SIZE = 50000


async def fetch_cve_data():
    logging.info("Starting cloning REPO")
    if not os.path.exists(LOCAL_PATH):
        os.makedirs(LOCAL_PATH)
        logging.info(f"Cloning repository from {REPO_URL} to {LOCAL_PATH}")
        Repo.clone_from(REPO_URL, LOCAL_PATH, depth=1)
    else:
        logging.info(f"Pulling latest changes in {LOCAL_PATH}")
        repo = Repo(LOCAL_PATH)
        start_time = datetime.now()
        repo.remotes.origin.pull()
        logging.info(f"Pull completed in {datetime.now() - start_time}")

    cve_folder_path = os.path.join(LOCAL_PATH, CVE_FOLDER)
    if not os.path.exists(cve_folder_path):
        logging.error(f"CVE folder {cve_folder_path} does not exist!")
        return

    logging.info(f"Starting fetch_cve_data from {cve_folder_path}")

    cve_records = []
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_FILES)

    async def process_file(file_path):
        async with semaphore:
            try:
                async with aiofiles.open(file_path, "r") as f:
                    file_content = await f.read()
                    cve_data = json.loads(file_content)
                    cve_records.append(cve_data)
            except Exception as e:
                logging.error(f"Error reading {file_path}: {e}")

    tasks = []
    for root, dirs, files in os.walk(cve_folder_path):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                tasks.append(process_file(file_path))

    await asyncio.gather(*tasks)

    # Отправка батчей
    for i in range(0, len(cve_records), BATCH_UPLOAD_SIZE):
        batch = cve_records[i:i + BATCH_UPLOAD_SIZE]
        await send_cve_data_to_api(batch)


async def send_cve_data_to_api(cve_records):
    if not cve_records:
        logging.info("No CVE records to send")
        return

    logging.info(f"Sending {len(cve_records)} CVE records to API")
    async with aiohttp.ClientSession() as session:
        try:
            payload = {"cve_records": cve_records}
            async with session.post(API_URL, json=payload) as response:
                if response.status == 200:
                    logging.info("CVE records successfully uploaded")
                else:
                    text = await response.text()
                    logging.error(f"Failed to upload CVE records: {response.status}, {text}")
        except Exception as e:
            logging.error(f"Exception during API request: {e}")


async def main():
    await asyncio.sleep(6)
    while True:
        try:
            await fetch_cve_data()
        except Exception as e:
            logging.error(f"Error in fetch_cve_data: {e}")
        logging.info(f"Sleeping for {FETCH_INTERVAL_HOURS} hours")
        await asyncio.sleep(FETCH_INTERVAL_HOURS * 3600)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Scraper stopped by user")
        sys.exit(0)
