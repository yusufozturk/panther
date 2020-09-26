FROM golang:1.15.2

LABEL description="The image responsible for our GraphQL API server"

ENV GRAPH_API_PORT=8000
ENV GO111MODULE=on

# Move all of our logic
RUN mkdir /code

# To a different folder so we don't pollute the root of our container
WORKDIR /code

# Copy the dependency files
COPY go.mod .
COPY go.sum .

# Install dependencies
RUN go mod download

# Copy all the necessary code for our GraphQL server
COPY internal/core/graph_api internal/core/graph_api

# Build the package
RUN go build internal/core/graph_api/main/server.go

# Run the server
CMD ["./server"]

# through the port chosen during build time (defaults to 8080)
EXPOSE ${GRAPH_API_PORT}