from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Union


class CVEBaseModel(BaseModel):
    published_date: datetime
    last_modified_date: datetime
    title: str
    description: str
    problem_types: Optional[str] = None

    class Config:
        orm_mode = True


class CVERecordCreate(CVEBaseModel):
    cve_id: str


class CVERecord(CVEBaseModel):
    cve_id: str
    id: int


class CVERecordUpdate(BaseModel):
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    title: Optional[str] = None
    description: Optional[str] = None
    problem_types: Optional[str] = None

    class Config:
        extra = "allow"


class CVEBatchUpload(BaseModel):
    cve_records: Union[list, dict]
