FROM alpine:3.20

RUN apk add --no-cache curl tzdata jq ca-certificates \
 && cd /tmp \
 && curl -fsSL -o c.tgz https://github.com/ikuaidev/ikuai-cli/releases/download/v1.0.18/ikuai-cli_linux_amd64.tar.gz \
 && echo "047318d14b4b7eace976b9baea5e34df5a68e532abf0841308898848eda4b593  c.tgz" | sha256sum -c - \
 && tar xzf c.tgz \
 && find . -name ikuai-cli -type f -exec install -m755 {} /usr/local/bin/ikuai-cli \; \
 && rm -rf /tmp/*

ENV TZ=Asia/Shanghai HOME=/data
COPY failover.sh /failover.sh
COPY chatgpt-controller.sh /chatgpt-controller.sh
CMD ["sh", "/failover.sh"]
