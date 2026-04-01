FROM python:3.12-slim

# Install pdflatex (texlive-base ~150MB, includes pdflatex + core fonts)
RUN apt-get update && \
    apt-get install -y --no-install-recommends texlive-base texlive-latex-extra && \
    rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd --create-home appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p output && chown appuser:appuser output

USER appuser

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/api/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
