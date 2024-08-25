from fastapi import APIRouter, Depends

from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from src.cve_app.crud import get_cve_record, create_cve_record, update_cve_record, delete_cve_record
from src.cve_app.schemas import CVERecord, CVERecordCreate, CVERecordUpdate
from src.db import get_db
from src.cve_app.exceptions import CVEAlreadyExistsException, CVENotFoundException


cve_app = APIRouter()


@cve_app.post("/cve/", response_model=CVERecord, status_code=status.HTTP_201_CREATED)
async def create_cve(cve: CVERecordCreate, db: AsyncSession = Depends(get_db)):
    db_cve = await get_cve_record(db, cve.cve_id)
    if db_cve:
        raise CVEAlreadyExistsException()
    return await create_cve_record(db, cve)


@cve_app.get("/cve/{cve_id}", response_model=CVERecord)
async def read_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    db_cve = await get_cve_record(db, cve_id)
    if db_cve is None:
        raise CVENotFoundException()
    return db_cve


@cve_app.put("/cve/{cve_id}", status_code=status.HTTP_200_OK)
async def update_cve(cve_id: str, updates: CVERecordUpdate, db: AsyncSession = Depends(get_db)):
    db_cve = await get_cve_record(db, cve_id)
    if db_cve is None:
        raise CVENotFoundException()
    await update_cve_record(db, cve_id, updates.dict(exclude_unset=True))
    await db.refresh(db_cve)
    return {"message": "CVE updated successfully"}


@cve_app.delete("/cve/{cve_id}", status_code=status.HTTP_200_OK)
async def delete_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    db_cve = await get_cve_record(db, cve_id)
    if db_cve is None:
        raise CVENotFoundException()
    await delete_cve_record(db, cve_id)
    return {"message": "CVE deleted successfully"}
