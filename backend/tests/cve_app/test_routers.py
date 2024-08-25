import pytest
import asyncio

from httpx import AsyncClient
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from starlette import status

from src.cve_app.models import CVERecord
from tests.conftest import client, db_async_session


async def _get_cve_by_id(cve_id: str, db: AsyncSession) -> CVERecord:
    query = select(CVERecord).where(CVERecord.cve_id == cve_id)
    result = await db.execute(query)
    db_cve = result.scalars().first()
    return db_cve


async def test_create_cve_record(client: AsyncClient, db_async_session: AsyncSession):
    cve_data = {
        "cve_id": "CVE-2024-12345",
        "published_date": "2024-08-01T00:00:00",
        "last_modified_date": "2024-08-10T00:00:00",
        "title": "Test CVE Record",
        "description": "This is a test CVE description.",
        "problem_types": "Test problem type",
    }

    response = await client.post("/cve/", json=cve_data)
    assert response.status_code == status.HTTP_201_CREATED

    created_cve = response.json()
    assert created_cve["cve_id"] == cve_data["cve_id"]

    db_cve = await db_async_session.get(CVERecord, created_cve["id"])
    assert db_cve is not None
    assert db_cve.cve_id == cve_data["cve_id"]


async def test_read_cve_record(client: AsyncClient, db_async_session: AsyncSession):
    cve = CVERecord(
        cve_id="CVE-2024-54321",
        published_date=datetime(2024, 8, 1, 0, 0, 0),
        last_modified_date=datetime(2024, 8, 10, 0, 0, 0),
        title="Test CVE Record",
        description="This is a test CVE description.",
        problem_types="Test problem type",
    )
    db_async_session.add(cve)
    await db_async_session.commit()

    response = await client.get(f"/cve/{cve.cve_id}")
    assert response.status_code == status.HTTP_200_OK

    fetched_cve = response.json()
    assert fetched_cve["cve_id"] == cve.cve_id


async def test_update_cve_record(client: AsyncClient, db_async_session: AsyncSession):
    cve = CVERecord(
        cve_id="CVE-2024-54322",
        published_date=datetime(2024, 8, 1, 0, 0, 0),
        last_modified_date=datetime(2024, 8, 10, 0, 0, 0),
        title="Initial CVE Record",
        description="Initial description.",
        problem_types="Initial problem type",
    )
    db_async_session.add(cve)
    await db_async_session.commit()

    update_data = {
        "title": "Updated CVE Record",
        "description": "Updated description.",
        "problem_types": "Updated problem type",
    }

    response = await client.put(f"/cve/{cve.cve_id}", json=update_data)
    assert response.status_code == status.HTTP_200_OK

    response = await client.get(f"/cve/{cve.cve_id}")
    fetched_cve = response.json()

    assert fetched_cve["title"] == update_data["title"]
    assert fetched_cve["description"] == update_data["description"]


async def test_delete_cve_record(client: AsyncClient, db_async_session: AsyncSession):
    cve = CVERecord(
        cve_id="CVE-2024-54323",
        published_date=datetime(2024, 8, 1, 0, 0, 0),
        last_modified_date=datetime(2024, 8, 10, 0, 0, 0),
        title="CVE to Delete",
        description="Description to delete.",
        problem_types="Problem type to delete",
    )
    db_async_session.add(cve)
    await db_async_session.commit()

    response = await client.delete(f"/cve/{cve.cve_id}")
    assert response.status_code == status.HTTP_200_OK

    db_cve = await _get_cve_by_id(cve.cve_id, db_async_session)

    assert db_cve is None


async def test_get_cve_list(client: AsyncClient, db_async_session: AsyncSession):
    cve1 = CVERecord(
        cve_id="CVE-2024-3001",
        published_date=datetime(2024, 4, 1),
        last_modified_date=datetime(2024, 4, 10),
        title="CVE 1",
        description="Description 1",
        problem_types="Type 1"
    )
    cve2 = CVERecord(
        cve_id="CVE-2024-3002",
        published_date=datetime(2024, 4, 2),
        last_modified_date=datetime(2024, 4, 12),
        title="CVE 2",
        description="Description 2",
        problem_types="Type 2"
    )

    db_async_session.add_all([cve1, cve2])
    await db_async_session.commit()

    response = await client.get("/cve-utils/list", params={"page": 1, "size": 2})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2


async def test_get_cve_by_text(client: AsyncClient, db_async_session: AsyncSession):
    cve1 = CVERecord(
        cve_id="CVE-2024-2001",
        published_date=datetime(2024, 3, 1),
        last_modified_date=datetime(2024, 3, 10),
        title="Important CVE",
        description="This is an important security vulnerability.",
        problem_types="Security"
    )
    db_async_session.add(cve1)
    await db_async_session.commit()

    response = await client.get("/cve-utils/search", params={"text": "important"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["cve_id"] == "CVE-2024-2001"
    assert "important" in data[0]["title"].lower()


async def test_get_cve_by_date_range(client: AsyncClient, db_async_session: AsyncSession):
    cve1 = CVERecord(
        cve_id="CVE-2024-1001",
        published_date=datetime(2024, 1, 1),
        last_modified_date=datetime(2024, 1, 10),
        title="CVE 1",
        description="Description 1",
        problem_types="Problem Type 1"
    )
    cve2 = CVERecord(
        cve_id="CVE-2024-1002",
        published_date=datetime(2024, 2, 1),
        last_modified_date=datetime(2024, 2, 10),
        title="CVE 2",
        description="Description 2",
        problem_types="Problem Type 2"
    )
    db_async_session.add_all([cve1, cve2])
    await db_async_session.commit()

    response = await client.get("/cve-utils/date-range", params={"start_date": "2024-01-01", "end_date": "2024-01-31"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["cve_id"] == "CVE-2024-1001"
