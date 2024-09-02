import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from .models import CVERecord


DATETIME_FORMATS = [
    '%Y-%m-%dT%H:%M:%S.%fZ',
    '%Y-%m-%dT%H:%M:%S.%f',
    '%Y-%m-%dT%H:%M:%SZ',
    '%Y-%m-%dT%H:%M:%S'
]


def __parse_datetime(datetime_str):
    for fmt in DATETIME_FORMATS:
        try:
            return datetime.strptime(datetime_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Time data '{datetime_str}' does not match any known format.")


async def process_single_cve(data, cve_records):
    try:
        cve_id = data.get('cveMetadata', {}).get('cveId', None)
        published_date_str = data.get('cveMetadata', {}).get('datePublished', None)
        last_modified_date_str = data.get('cveMetadata', {}).get('dateUpdated', None)

        published_date = __parse_datetime(published_date_str) if published_date_str else None
        last_modified_date = __parse_datetime(last_modified_date_str) if last_modified_date_str else None

        cna = data.get('containers', {}).get('cna', {})
        title = cna.get('descriptions', [{}])[0].get('value', "Unknown Title")
        description = cna.get('descriptions', [{}])[0].get('value', "No description available")
        problem_types = ", ".join(
            [
                pt.get('descriptions', [{}])[0].get('description', '')
                for pt in cna.get('problemTypes', [])
            ]
        ) if cna.get('problemTypes') else None

        if cve_id is None or published_date is None or last_modified_date is None:
            logging.warning(f"Skipping CVE record due to missing required fields: {cve_id}")
            return

        cve_record = CVERecord(
            cve_id=cve_id,
            published_date=published_date,
            last_modified_date=last_modified_date,
            title=title,
            description=description,
            problem_types=problem_types
        )
        cve_records.append(cve_record)
        logging.debug(f"Processed CVE record {cve_id}")

    except Exception as e:
        logging.error(f"Error processing CVE record: {e}")
