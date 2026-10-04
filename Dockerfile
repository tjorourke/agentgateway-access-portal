FROM python:3.13.7-slim
LABEL org.opencontainers.image.source="https://github.com/tjorourke/agentgateway-access-portal"
LABEL org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml ./
COPY portal ./portal
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home portal
USER 10001
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "--timeout", "90", "--access-logfile", "-", "--access-logformat", "%(m)s %(U)s %(s)s", "portal.web:create_app()"]
