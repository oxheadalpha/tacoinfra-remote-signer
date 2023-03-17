import logging
import sys
from os import environ, path

import boto3
from flask import Flask, Response, json, jsonify, request
from werkzeug.exceptions import HTTPException

from src.ddbchainratchet import DDBChainRatchet
from src.hsmsigner import HsmSigner
from src.kms_signer import KmsSigner, FileRatchet
from src.sigreq import SignatureReq
from src.validatesigner import ValidateSigner

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#
# The config file (keys.json) has a structure:
#
# config = {
#     'hsm_username': 'resigner',
#     'hsm_slot': 1,
#     'hsm_lib': '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so',
#     'keys': {
#         'tz3aTaJ3d7Rh4yXpereo4yBm21xrs4bnzQvW': {
#             'public_key':
#                 'p2pk67jx4rEadFpbHdiPhsKxZ4KCoczLWqsEpNarWZ7WQ1SqKMf7JsS',
#             'private_handle': 7,
#             'public_handle': 9
#         }
#     },
#     'policy': {
#         'baking': 1,		# just a boolean
#         'voting': ['pass'],	# a list of permitted votes
#     }
# }
config = {}

keys_path = "./signer-config/keys.json"
if path.isfile(keys_path):
    with open(keys_path, "r") as myfile:
        json_blob = myfile.read().replace("\n", "")
        config["keys"] = json.loads(json_blob)
        logging.info(f"Loaded config contains: {json.dumps(config, indent=2)}")

try:
    signer_type = sys.argv[1]
except:
    signer_type = None

# EKS HAS $AWS_REGION
REGION = environ["REGION"]
SIGNER = None

if signer_type == "kms":
    client = boto3.client("kms", region_name=REGION)
    # file_ratchet = FileRatchet()
    SIGNER = KmsSigner(client, ratchet=FileRatchet)
    # SIGNER = KmsSigner(client, ratchet=file_ratchet)
elif signer_type == "hsm":
    ratchet = DDBChainRatchet(REGION, environ["DDB_TABLE"])
    hsm_signer = HsmSigner(config)
    SIGNER = ValidateSigner(config, ratchet=ratchet, subsigner=hsm_signer)
else:
    raise Exception("Either 'hsm' or 'kms' must be provided as the signer type.")


def logreq(sigreq, msg):
    if sigreq != None:
        logging.info(f"Request: {sigreq.get_logstr()}:{msg}")


@app.route("/keys/<key_hash>", methods=["GET", "POST"])
def sign(key_hash):
    response = None
    sigreq = None
    try:
        if key_hash in config["keys"]:
            key_data = config["keys"][key_hash]
            if request.method == "POST":
                sigreq = SignatureReq(request.get_json(force=True))
                response = jsonify({"signature": SIGNER.sign(sigreq, key_data, key_hash=key_hash)})
            else:
                response = jsonify({"public_key": key_data["public_key"]})
        else:
            logging.warning(f"Couldn't find key {key_hash}")
            response = Response("Key not found", status=404)
    except HTTPException as e:
        logging.error(e)
        logreq(sigreq, "Failed")
        raise
    except Exception as e:
        data = {"error": str(e)}
        logging.error(f"Exception thrown during request:", exc_info=True)
        response = app.response_class(
            response=json.dumps(data), status=500, mimetype="application/json"
        )
        logreq(sigreq, "Failed")
        return response

    logreq(sigreq, "Success")

    return response


@app.route('/authorized_keys', methods=['GET'])
def authorized_keys():
    return app.response_class(
        response=json.dumps({}),
        status=200,
        mimetype='application/json'
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
