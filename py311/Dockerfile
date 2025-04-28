FROM debian:12

RUN apt-get update && apt-get install -y build-essential gdb lcov pkg-config \
        libbz2-dev libffi-dev libgdbm-dev libgdbm-compat-dev liblzma-dev \
        libncurses5-dev libreadline6-dev libsqlite3-dev libssl-dev \
        lzma lzma-dev tk-dev uuid-dev zlib1g-dev git python3
        
ADD armor-marshal-specialization-311.patch /armor-marshal-specialization-311.patch

RUN git clone --depth 1 --branch 3.11 https://github.com/python/cpython.git && \
    cd cpython && \
    patch -p1 -i ../armor-marshal-specialization-311.patch && \
    ./configure && \
    make regen-all

RUN echo '#!/bin/sh\n/cpython/python -X nospecialization "$@"' > /run_python.sh && \
    chmod +x /run_python.sh

ENTRYPOINT [ "/run_python.sh" ]
