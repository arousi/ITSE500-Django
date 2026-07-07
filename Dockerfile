FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
 && rm -rf /var/lib/apt/lists/*

# copy requirements first to leverage layer caching
COPY requirements.txt /app/
COPY requirements/ /app/requirements/

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# copy project
COPY . /app/

# ensure entrypoint is executable
RUN chmod +x /app/entrypoint.sh

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "prompeteer_server.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
