ARG BUILD_FROM
FROM ${BUILD_FROM} AS llama-builder

# Pin a known-good llama.cpp release rather than tracking main.
ARG LLAMA_CPP_REF=b4713

RUN apk add --no-cache build-base cmake git \
    && git clone --depth 1 --branch ${LLAMA_CPP_REF} https://github.com/ggml-org/llama.cpp.git /src/llama.cpp \
    && cmake -S /src/llama.cpp -B /src/llama.cpp/build -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=OFF \
    && cmake --build /src/llama.cpp/build --target llama-server -j"$(nproc)"

FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-pip libgomp

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
