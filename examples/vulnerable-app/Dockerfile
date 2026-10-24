# Intentionally insecure Dockerfile for the IaC scanner demo.
FROM python:latest@sha256:67ee282bdbe5ece1e38ea94fa68f1420e969e6176e6c826b9acc931055011bfb

WORKDIR /app
COPY . /app

RUN pip install -r requirements.txt

# No USER directive: container runs as root (iac scanner: CWE-250).
EXPOSE 5000
CMD ["python", "app.py"]
