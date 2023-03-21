#!/bin/sh

set -xe

CMD="$1"
shift

case "$CMD" in
	hsm)  exec hsm-remote-signer.sh	"$@"	;;
	# kms)  python3 signer.py	"kms" ;;
	kms)  if ! python3 signer.py "kms"; then
          echo "Failed to start kms signer."
          exit 1
        fi
esac

#
# As we exec above, reaching here means that we did not
# find the command we were provided.

echo "ERROR: could not find \"$CMD\"."
echo
echo "Valid options are:"
echo "	hsm"
echo "	kms"

exit 1
