from fastapi import HTTPException, status


class CVENotFoundException(HTTPException):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CVE not found."
        )


class CVEAlreadyExistsException(HTTPException):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="CVE already exist."
        )

