# Built by goreleaser (dockers_v2): the build context holds the binary for
# each platform under $TARGETPLATFORM/.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/azhaq /usr/local/bin/azhaq
COPY LICENSE /usr/share/doc/azhaq/LICENSE
COPY third_party /usr/share/doc/azhaq/third_party
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/azhaq"]
