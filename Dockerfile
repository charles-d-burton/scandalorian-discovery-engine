# FROM golang:latest as build-arm

# RUN mkdir /app
# WORKDIR /app
# COPY ./ .
# RUN GOOS=linux GOARCH=arm go build -a -installsuffix cgo -ldflags="-w -s" -o discovery-engine

# FROM golang:latest as build-arm64
# RUN mkdir /app
# WORKDIR /app
# COPY ./ .
# RUN GOOS=linux GOARCH=arm64 go build -a -installsuffix cgo -ldflags="-w -s" -o discovery-engine


FROM golang:latest as build
RUN mkdir /app
WORKDIR /app
COPY ./ .
RUN go build -a -installsuffix cgo -ldflags="-w -s" -o discovery-engine

#FROM scratch as arm
#COPY --from=build-arm /app/discovery-engine /go/bin/discovery-engine
#ENTRYPOINT [ "/go/bin/discovery-engine" ]

#FROM scratch as arm64
#COPY --from=build-arm64 /app/discovery-engine /go/bin/discovery-engine
#ENTRYPOINT ["/go/bin/discovery-engine"]

FROM alpine:latest
COPY --from=build /app/discovery-engine /go/bin/discovery-engine
ENTRYPOINT ["/go/bin/discovery-engine"]
