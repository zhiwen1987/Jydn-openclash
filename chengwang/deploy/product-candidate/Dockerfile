FROM scratch
ARG SOURCE_COMMIT
LABEL org.opencontainers.image.revision=$SOURCE_COMMIT
LABEL org.chengwang.boundary=ISOLATED_PRODUCT_CANDIDATE
COPY --chown=0:0 rootfs/ /
USER 10001:10001
WORKDIR /app
ENTRYPOINT ["/app/image-trust-api"]
