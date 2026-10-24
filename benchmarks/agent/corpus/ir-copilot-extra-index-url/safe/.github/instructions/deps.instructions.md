---
applyTo: "requirements*.txt"
---

# Dependency instructions

- Install Python packages with pip from PyPI.
- Our private packages live on an authenticated index configured in the CI
  secret `PIP_INDEX_URL`; do not add extra untrusted or plain-HTTP indexes in
  this repo.
- Pin versions after installing.
