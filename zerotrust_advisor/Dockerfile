ARG BUILD_FROM
FROM ${BUILD_FROM} AS llama-builder

# Pin a known-good llama.cpp release rather than tracking main.
ARG LLAMA_CPP_REF=b10612

# BUILD_SHARED_LIBS=OFF: the default build produces llama-server dynamically
# linked against several sibling libggml*/libllama .so files that live only
# in the build tree — copying just the executable into the final stage left
# it unable to resolve its own symbols at runtime ("Error relocating
# /usr/local/bin/llama-server: ...: symbol not found"), caught only once
# actually deployed since a static binary has no such dependency to miss.
# curl-dev: without it, cmake silently builds llama-server with its -hf
# (fetch straight from Hugging Face) option disabled — found only by
# actually running it ("built without libcurl, downloading ... not
# supported"), not by the build succeeding.
RUN apk add --no-cache build-base cmake git curl-dev linux-headers \
    && git clone --depth 1 --branch ${LLAMA_CPP_REF} https://github.com/ggml-org/llama.cpp.git /src/llama.cpp \
    && cmake -S /src/llama.cpp -B /src/llama.cpp/build -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=OFF -DBUILD_SHARED_LIBS=OFF -DLLAMA_CURL=ON \
    && cmake --build /src/llama.cpp/build --target llama-server -j"$(nproc)"

FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-pip libgomp libstdc++ curl

COPY --from=llama-builder /src/llama.cpp/build/bin/llama-server /usr/local/bin/llama-server

WORKDIR /opt/zerotrust_advisor
# s6 services don't inherit this WORKDIR as their own CWD, so the "app"
# package needs to be on the path explicitly, not just importable from here.
ENV PYTHONPATH=/opt/zerotrust_advisor
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY app ./app
COPY rootfs /

RUN chmod a+x /etc/s6-overlay/s6-rc.d/*/run

LABEL \
    io.hass.name="Zero-Trust LAN Advisor" \
    io.hass.description="Passive firewall/flow log analysis with LLM-assisted zero-trust rule recommendations" \
    io.hass.type="addon"
