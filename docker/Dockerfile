# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile  –  Infer + Clang/ASan environment
#
# Build:  docker build -t static-verifier -f docker/Dockerfile .
# Run:    docker run --rm -it -v $(pwd):/workspace static-verifier bash
# ─────────────────────────────────────────────────────────────────────────────

FROM facebook/infer:latest

# Install Clang, Python 3, and other tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang          \
        clang-tools    \
        gcc            \
        python3        \
        python3-pip    \
        python3-venv   \
        curl           \
        git            \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
WORKDIR /workspace
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "main.py"]
