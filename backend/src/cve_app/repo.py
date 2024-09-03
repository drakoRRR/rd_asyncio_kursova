import logging
from datetime import datetime
from typing import Optional, Union

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, delete
from .models import CVERecord as CVERecordModel
from .schemas import CVERecordCreate
from .services import process_single_cve

from fastapi_pagination.ext.sqlalchemy import paginate


async def get_cve_record(db: AsyncSession, cve_id: str):
    query = select(CVERecordModel).where(CVERecordModel.cve_id == cve_id)
    result = await db.execute(query)
    return result.scalars().first()


async def create_cve_record(db: AsyncSession, cve: CVERecordCreate):
    db_cve = CVERecordModel(**cve.dict())
    db.add(db_cve)
    await db.commit()
    await db.refresh(db_cve)
    return db_cve


async def update_cve_record(db: AsyncSession, cve_id: str, updates: dict):
    query = update(CVERecordModel).where(
        CVERecordModel.cve_id == cve_id
    ).values(**updates).execution_options(synchronize_session="fetch")
    await db.execute(query)
    await db.commit()


async def delete_cve_record(db: AsyncSession, cve_id: str):
    query = delete(CVERecordModel).where(CVERecordModel.cve_id == cve_id)
    await db.execute(query)
    await db.commit()


async def search_cve_by_date_range(db: AsyncSession, start_date: Optional[datetime], end_date: Optional[datetime]):
    query = select(CVERecordModel)

    if start_date:
        query = query.where(CVERecordModel.published_date >= start_date)

    if end_date:
        query = query.where(CVERecordModel.published_date <= end_date)

    result = await db.execute(query)
    return result.scalars().all()


async def search_cve_by_text(db: AsyncSession, text: str):
    query = select(CVERecordModel).where(
        (CVERecordModel.title.ilike(f"%{text}%")) |
        (CVERecordModel.description.ilike(f"%{text}%")) |
        (CVERecordModel.problem_types.ilike(f"%{text}%"))
    )

    result = await db.execute(query)
    return result.scalars().all()


async def list_cve_records(db: AsyncSession, page: int, size: int):
    query = select(CVERecordModel)
    return await paginate(db, query)


async def upload_batch_cves(db: AsyncSession, data_list: Union[list, dict]):
    existing_records = await db.execute(select(CVERecordModel))
    existing_records = {record.cve_id: record for record in existing_records.scalars().all()}

    cve_records_to_add = []
    cve_records_to_update = []

    for data in data_list:
        if isinstance(data, list):
            for item in data:
                await process_single_cve(item, existing_records, cve_records_to_add, cve_records_to_update)
        else:
            await process_single_cve(data, existing_records, cve_records_to_add, cve_records_to_update)

    try:
        if cve_records_to_add:
            db.add_all(cve_records_to_add)
        if cve_records_to_update:
            for record in cve_records_to_update:
                await db.merge(record)

        await db.commit()
        logging.info(f"Successfully saved or updated CVE records in the database.")
    except IntegrityError as e:
        await db.rollback()
        logging.error(f"Error saving CVE records: {e}")
        return {"message": "Batch upload failed"}