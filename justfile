generate:
    cd tools; go generate ./...

install:
    go install .

update:
  aqua up
  aqua update-checksum --prune
  aqua i