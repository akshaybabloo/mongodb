# Use an official Go image as a parent image
FROM golang:1.24-bookworm

# Set the working directory inside the container
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y wget cmake libssl-dev build-essential && \
    apt-get purge -y libmongocrypt-dev

# Download and install libmongocrypt
RUN wget https://github.com/mongodb/libmongocrypt/archive/refs/tags/1.14.1.tar.gz && \
    tar -xzf 1.14.1.tar.gz && \
    cd libmongocrypt-1.14.1/ && \
    mkdir cmake-build && \
    cd cmake-build && \
    cmake -DBUILD_VERSION=1.14.1 .. && \
    make install && \
    ldconfig

# Copy the Go modules files
ENV CGO_ENABLED=1

# Copy the Go modules files
COPY go.mod go.sum ./

# Clear Go module cache and download Go modules
RUN go clean -modcache && go clean -cache && go mod download

# Copy the source code
COPY . .

# Set CGO flags to find libmongocrypt
ENV CGO_CFLAGS="-I/usr/local/include"
ENV CGO_LDFLAGS="-L/usr/local/lib"

# Run the tests with the cse tag
CMD ["go", "test", "-v", "-tags", "cse"]

