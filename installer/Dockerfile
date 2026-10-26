ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
COPY runtime/upstream/ /
RUN mv /subscription-controller.py /subscription_impl.py
COPY runtime/portable_subscriptions.py /subscription-controller.py
COPY runtime/stack_boot.py runtime/setup_kuma.js /
COPY local-subscription/ /local-subscription/
COPY core /local-subscription/core
RUN chmod 700 /local-subscription/core /*.sh && \
    ln -sf /local-subscription/core /opt/mihomo-validate && \
    sha256sum /local-subscription/core | cut -d' ' -f1 > /opt/mihomo-validate.sha256 && \
    python3 -B -m compileall -q /local-subscription /subscription-controller.py /subscription_impl.py && \
    sh -n /failover.sh
HEALTHCHECK --interval=15s --timeout=10s --start-period=60s --retries=5 CMD python3 -B /unified_runtime.py health && curl -fsS --max-time 3 http://127.0.0.1:8081/health >/dev/null && curl -fsS --max-time 3 http://127.0.0.1:8082/health >/dev/null
CMD ["python3", "-B", "/stack_boot.py"]
