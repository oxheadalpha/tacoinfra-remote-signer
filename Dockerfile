FROM python:3.9-slim

COPY requirements.txt /

RUN     apt-get update							\
     && apt-get install -y gcc python3-dev curl				\
     && apt-get install -y libsodium23   libsecp256k1-0   libgmp10	\
     && apt-get install -y libsodium-dev libsecp256k1-dev libgmp-dev	\
     && pip --no-cache install -r /requirements.txt			\
     && apt-get purge -y gcc python3-dev				\
     && apt-get purge -y libsodium-dev libsecp256k1-dev libgmp-dev	\
     && apt-get autoremove -y						\
     && rm -rf /var/lib/apt /var/cache/apt /root/.cache

#
# XXXrcd: We should fetch a particular version of these libraries:

RUN	TOP=https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient	\
	VER=Bionic							\
	CLIENT=cloudhsm-client_latest_u18.04_amd64.deb			\
	PKCS11=cloudhsm-client-pkcs11_latest_u18.04_amd64.deb;		\
									\
	for i in $CLIENT $PKCS11; do					\
		curl -o "$i" "$TOP/$VER/$i";				\
		apt-get install -y "$i";				\
		rm -f "$i";						\
	done

COPY src/. /src/
COPY signer.py /

ENTRYPOINT ["/src/start-remote-signer.sh"]
