from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, delete
from .models import CVERecord as CVERecordModel
from .schemas import CVERecordCreate


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
