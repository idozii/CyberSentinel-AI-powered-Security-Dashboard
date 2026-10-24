FROM python:3.12-alpine

RUN adduser -D -H appuser
WORKDIR /app
COPY --chown=appuser:appuser app.py /app/app.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER appuser
EXPOSE 8000
CMD ["python", "-u", "/app/app.py"]
