FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
WORKDIR /app
COPY pyproject.toml ./
RUN uv pip install --system .
COPY . .
# Copy shared auth module (build context must include ghostlabs_auth/)
COPY ghostlabs_auth/ ./ghostlabs_auth/
ENV PYTHONUNBUFFERED=1
EXPOSE 7012
CMD ["fastmcp", "run", "server.py:mcp", "--transport", "sse", "--host", "0.0.0.0", "--port", "7012"]
