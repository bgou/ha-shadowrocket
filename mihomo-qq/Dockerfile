FROM metacubex/mihomo:v1.19.34
RUN apk add --no-cache python3 py3-yaml iproute2
COPY rootfs/ /
RUN chmod 755 /run.py
ENTRYPOINT ["python3", "-u", "/run.py"]
