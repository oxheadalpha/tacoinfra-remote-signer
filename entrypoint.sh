#!/bin/sh

set -xe

CMD="$1"
shift

case "$CMD" in
	hsm)  exec hsm-remote-signer.sh	"$@"	;;
	kms)  if ! python3 signer.py "kms"; then
          echo "Failed to start kms signer."
          exit 1
        fi
esac

echo "ERROR: could not find \"$CMD\"."
echo
echo "Valid options are:"
echo "	hsm"
echo "	kms"

exit 1
