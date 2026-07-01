# Isolated environment for the job-title department classifier.
#
# Build:
#   docker build -t brutus-job-classifier job-classifier/
#
# Train (mounts data/ and model/ so artifacts land on the host):
#   docker run --rm \
#     -v "$PWD/job-classifier/data:/app/data" \
#     -v "$PWD/job-classifier/model:/app/model" \
#     -v "$PWD/job-classifier/.hf-cache:/root/.cache/huggingface" \
#     brutus-job-classifier python train.py
#
# Classify a single title:
#   docker run --rm \
#     -v "$PWD/job-classifier/model:/app/model" \
#     -v "$PWD/job-classifier/.hf-cache:/root/.cache/huggingface" \
#     brutus-job-classifier python classify.py --title "Director of IT"
FROM python:3.11-slim

WORKDIR /app

# Keep Python quiet and unbuffered so container logs stream in real time.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HUB_DISABLE_TELEMETRY=1

# Install deps first so the layer caches across code edits.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code (data/ and model/ are provided as mounts at run time).
COPY categories.py generate_data.py train.py classify.py refine.py ./

CMD ["python", "classify.py", "--help"]
