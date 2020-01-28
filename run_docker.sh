#!/bin/bash

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

# must be run as root
[[ "$EUID" -ne 0 ]] && { echo "This script must be run with root privileges!"; exit 1; }



docker build --no-cache -t edk-builder/edk-builder -f $DIR/Dockerfile $DIR


docker run -it --privileged -v "$DIR":/root/ -u root -w /root edk-builder/edk-builder /bin/bash