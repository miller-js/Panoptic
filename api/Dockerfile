FROM golang:1.26-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /panoptic-api .

FROM alpine:3.20

COPY --from=build /panoptic-api /panoptic-api

EXPOSE 8080

CMD ["/panoptic-api"]
