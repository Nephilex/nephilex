# nephilex-ignore: docker-user-root reason="ClusterFuzzLite build image, never deployed; the OSS-Fuzz base-builder compile step runs as root to install the package and write fuzzers to OUT"
# ClusterFuzzLite build image for the fuzz/ harnesses (atheris, Python).
# Pinned by digest like every other image in this repository.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9
COPY . $SRC/nephilex
WORKDIR $SRC/nephilex
COPY .clusterfuzzlite/build.sh $SRC/
