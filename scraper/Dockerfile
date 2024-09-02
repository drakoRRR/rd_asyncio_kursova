FROM --platform=linux/amd64 python:3.12-alpine

ENV PYTHONUNBUFFERED=True
ENV PYTHONPATH=/scraper

WORKDIR /scraper

RUN apk update && apk add --no-cache git

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app/scraper.py"]