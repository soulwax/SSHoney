# File: Dockerfile

FROM alpine:3.9 as builder
RUN apk add --no-cache build-base
ADD sshoney.c Makefile /
RUN make


FROM alpine:3.9

COPY --from=builder /sshoney /

EXPOSE 2222/tcp

ENTRYPOINT ["/sshoney"]

CMD ["-v"]