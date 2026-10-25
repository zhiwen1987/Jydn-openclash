# Pin BASE_IMAGE to the accepted local r2 image ID when building in production.
ARG BASE_IMAGE=lan-center-unified:20261025-r2
FROM ${BASE_IMAGE}
USER root
COPY route_quality.py /route_quality.py
COPY strict_custom_guard.py /strict_custom_guard.py
COPY strict_select.py /strict_select.py
RUN python3 -B -c "compile(open('/route_quality.py').read(), '/route_quality.py', 'exec')"
