# No public ports. This image only runs an offline release rehearsal.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv/cybersentinel
COPY deployment/step26/requirements-smoke.txt ./requirements-smoke.txt
RUN python -m pip install --no-cache-dir -r requirements-smoke.txt
# Explicit source allowlist avoids accidentally copying DSNs and local logs.
COPY pyproject.toml ./
COPY cybersentinel_agent ./cybersentinel_agent
COPY hosted_api ./hosted_api
COPY owner_api ./owner_api
COPY scripts ./scripts
RUN python -m pip install --no-cache-dir -e . \
    && groupadd --system --gid 10001 cybersentinel \
    && useradd --system --uid 10001 --gid 10001 --no-create-home cybersentinel \
    && chown -R 10001:10001 /srv/cybersentinel
USER 10001:10001
CMD ["python", "-m", "scripts.step25_release"]
