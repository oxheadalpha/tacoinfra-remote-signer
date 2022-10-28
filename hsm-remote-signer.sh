#!/bin/sh
# Starts the Remote Signer
# -----------------------------------------------------------------------
# Requires the following environment variables to be set
# $REGION = the AWS region where the remote signer is deployed
# $STACKNAME is the name of the stack
# $HSMID = A unique identifier for the CloudHSM
# In addition, a Systems Manager parameter should be set that contains
# the following.  This will be created automatically when you launch the
# CloudFormation template that creates the autoscaling group of remote
# signers:
# [
#	{
#	  "hsm_username": "${HSMUser}",
#	  "hsm_slot": ${HSMSlot},
#	  "hsm_lib": "${HSMLibFile}",
#	  "node_addr": "${NodeAddress}",
#	  "keys": {
#	    "${HSMPubKey}": {
#	      "hash": "${HSMPubKeyHash}",
#	      "private_handle": ${HSMPrivKeyHandle},
#	      "public_handle": ${HSMPubKeyHandle}
#	    }
#	  }
#	}
# ]

aws_login() {
	TOP=http://169.254.169.254/latest/meta-data/iam/security-credentials/

	ROLE="$(curl -s $TOP)"
	JSON="$(curl -s "$TOP/$ROLE")"

	export AWS_ACCESS_KEY_ID="$(echo "$JSON"     | jq -r .AccessKeyId)"
	export AWS_SECRET_ACCESS_KEY="$(echo "$JSON" | jq -r .SecretAccessKey)"
	export AWS_SESSION_TOKEN="$(echo "$JSON"     | jq -r .Token)"
}

aws_setup_keys_json() {
	aws --region=$REGION ssm get-parameters		\
	    --name /hsm/$HSMID/$STACKNAME/keys		\
	    --output json --query Parameters[*].Value	\
	| jq -rc .[0] | jq .[0]				\
	> keys.json
}

aws_get_CA() {
	> /opt/cloudhsm/etc/customerCA.crt		\
	aws --region=$REGION ssm get-parameters		\
	    --name /hsm/${HSMID}/customerCA.crt		\
	    --with-decryption --output text		\
	    --query Parameters[*].Value
}

aws_load_password() {
	echo "Loading password from SSM..."
	export HSM_PASSWORD=`aws --region=$REGION ssm get-parameters \
		--name /hsm/$HSMID/password \
		--with-decryption \
		--output text \
		--query 'Parameters[*].Value'`

	if [ $? -ne 0 ]; then
		echo "SSM Error retrieving password"
		exit 1
	fi
}

aws_set_hsm_address() {
	/opt/cloudhsm/bin/configure -a ${HSMADDR}
}

start_remote_signer() {
	echo "Starting remote signer..."
	# FLASK_APP=signer /usr/local/bin/flask run --host=0.0.0.0
  python3 signer.py hsm
}

MISSING=
require_var() {
	eval VAR=\"\$$1\"

	if [ -z "$VAR" ]; then
		MISSING="$MISSING $1"
	fi
}

usage() {
	1>&2 echo "$@"
	1>&2 echo "usage: $0"
	exit 1
}

# make sure that we have the env vars:

for i in DDB_TABLE DD_MUTEX_TABLE_NAME REGION STACKNAME HSMID HSMADDR; do
	require_var $i
done

if [ -n "$MISSING" ]; then
	usage "some env vars are missing: $MISSING"
fi

echo "All required env vars passed in"

# main

aws_login
aws_setup_keys_json
aws_get_CA
aws_load_password
aws_set_hsm_address

start_remote_signer
