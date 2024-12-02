import subprocess
import json
from io import StringIO
from typing import List, Tuple
import csv
from io import StringIO
from google.cloud import storage
import base64
import google.cloud.kms as kms
import re
import os
import argparse
import configparser

config = configparser.ConfigParser()
config.read('config.env')



credentialConfig = {
    "type": "external_account",
    "audience": "//iam.googleapis.com/{wip}",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "token_url": "https://sts.googleapis.com/v1/token",
    "credential_source": {
    "file": "/run/container_launcher/attestation_verifier_claims_token"
    },
    "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{SA}:generateAccessToken"
}


# Constants for Primus and Secundus (replace with actual values)
# PRIMUS_BUCKET_NAME = "PRIMUS_INPUT_STORAGE_BUCKET"
# PRIMUS_DATA_PATH = "primus_enc_customer_list.csv"
# PRIMUS_KEY_NAME = "projects/PRIMUS_PROJECT_ID/locations/global/keyRings/PRIMUS_ENC_KEYRING/cryptoKeys/PRIMUS_ENC_KEY"
# PRIMUS_WIP_PROVIDER_NAME = "projects/PRIMUS_PROJECT_NUMBER/locations/global/workloadIdentityPools/PRIMUS_WORKLOAD_IDENTITY_POOL/providers/PRIMUS_WIP_PROVIDER"
# PRIMUS_KEY_ACCESS_SERVICE_ACCOUNT_EMAIL = "PRIMUS_SERVICE_ACCOUNT@PRIMUS_PROJECT_ID.iam.gserviceaccount.com"

# SECUNDUS_BUCKET_NAME = "SECUNDUS_INPUT_STORAGE_BUCKET"
# SECUNDUS_DATA_PATH = "secundus_enc_customer_list.csv"
# SECUNDUS_KEY_NAME = "projects/SECUNDUS_PROJECT_ID/locations/global/keyRings/SECUNDUS_ENC_KEYRING/cryptoKeys/SECUNDUS_ENC_KEY"
# SECUNDUS_WIP_PROVIDER_NAME = "projects/SECUNDUS_PROJECT_NUMBER/locations/global/workloadIdentityPools/SECUNDUS_WORKLOAD_IDENTITY_POOL/providers/SECUNDUS_WIP_PROVIDER"
# SECUNDUS_KEY_ACCESS_SERVICE_ACCOUNT_EMAIL = "SECUNDUS_SERVICE_ACCOUNT@SECUNDUS_PROJECT_ID.iam.gserviceaccount.com"

# PRIMUS_BUCKET_NAME = "primus-pj-01-input-buc"
# PRIMUS_DATA_PATH = "primus_enc_customer_list.csv"
# PRIMUS_KEY_NAME = "projects/primus-pj-01/locations/global/keyRings/primus-pj-01-enc-kr/cryptoKeys/primus-pj-01-enc-key-01"
# PRIMUS_WIP_PROVIDER_NAME = "projects/675427998709/locations/global/workloadIdentityPools/primus-pj-01-wip/providers/primus-pj-01-prov"
# PRIMUS_KEY_ACCESS_SERVICE_ACCOUNT_EMAIL = "primus-pj-01-sa@primus-pj-01.iam.gserviceaccount.com"

# SECUNDUS_BUCKET_NAME = "secundus-pj-01-input-buc"
# SECUNDUS_DATA_PATH = "secundus_enc_customer_list.csv"
# SECUNDUS_KEY_NAME = "projects/secundus-pj-01/locations/global/keyRings/secundus-pj-01-enc-kr/cryptoKeys/secundus-pj-01-enc-key-01"
# SECUNDUS_WIP_PROVIDER_NAME = "projects/22317815467/locations/global/workloadIdentityPools/secundus-pj-01-wip/providers/secundus-pj-01-prov"
# SECUNDUS_KEY_ACCESS_SERVICE_ACCOUNT_EMAIL = "secundus-pj-01-sa@secundus-pj-01.iam.gserviceaccount.com"


def replace_placeholders(data: dict, replacements: dict) -> dict:
    result = {}
    for key, value in data.items():
        if isinstance(value, str):
            for placeholder, replacement in replacements.items():
                value = value.replace(f"{{{placeholder}}}", str(replacement))
        elif isinstance(value, dict):
              value = replace_placeholders(value, replacements)
        result[key] = value
    return result

def decrypt_data(key_name, trusted_service_account_email, wip_provider_name, encrypted_data):
    
    """Decrypts the given encrypted data using the provided KMS key."""
    replacements = {
        "wip": wip_provider_name,
        "SA": trusted_service_account_email
        }
    credential_config = json.dumps(replace_placeholders(credentialConfig, replacements))

    kms_client = kms.KeyManagementServiceClient(credentials=credential_config)

    ciphertext_crc32c = crc32c(encrypted_data)

    decrypt_request = {
        "name": key_name,
        "ciphertext": encrypted_data,
        "ciphertext_crc32c": ciphertext_crc32c,
    }

    decrypt_response = kms_client.decrypt(request=decrypt_request)

    if not decrypt_response.plaintext_crc32c == crc32c(decrypt_response.plaintext):
        raise Exception(
            "The response received from the server was corrupted in-transit"
            )
    # print(f"Plaintext: {decrypt_response.plaintext!r}")
    return decrypt_response.plaintext

def crc32c(data: bytes) -> int:
    """
    Calculates the CRC32C checksum of the provided data.
    Args:
        data: the bytes over which the checksum should be calculated.
    Returns:
        An int representing the CRC32C checksum of the provided bytes.
    """
    import crcmod  # type: ignore

    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
    return crc32c_fun(data)

def read_from_bucket(table_info):
    """Reads and decrypts data from a CSV file in a Google Cloud Storage bucket."""
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(table_info["bucket_name"])
        blob = bucket.blob(table_info["data_path"])

        # Download the file content as a string
        encrypted_data = blob.download_as_string()    


        decrypted_data = decrypt_data(
                table_info["key_name"],
                table_info["key_access_service_account_email"],
                table_info["wip_provider_name"],
                encrypted_data,
           )
    
        csv_reader = csv.reader(decrypted_data.decode().splitlines())
        customer_data = list(csv_reader)
        return customer_data

    except Exception as e:
        print(f"Error reading file: {e}")



def read_in_primus_table():
    """Reads and decrypts data from the Primus table."""
    primus_table_info = {
        "bucket_name": config.get('PRIMUS','PRIMUS_BUCKET_NAME'),
        "data_path": config.get('PRIMUS','PRIMUS_DATA_PATH'),
        "key_name": config.get('PRIMUS','PRIMUS_KEY_NAME'),
        "key_access_service_account_email": config.get('PRIMUS','PRIMUS_KEY_ACCESS_SERVICE_ACCOUNT_EMAIL'),
        "wip_provider_name": config.get('PRIMUS','PRIMUS_WIP_PROVIDER_NAME'),
    }
    return read_from_bucket(primus_table_info)


def read_in_secundus_table():
    """Reads and decrypts data from the Secundus table."""
    secundus_table_info = {
        "bucket_name": config.get('SECUNDUS','SECUNDUS_BUCKET_NAME'),
        "data_path": config.get('SECUNDUS','SECUNDUS_DATA_PATH'),
        "key_name": config.get('SECUNDUS','SECUNDUS_KEY_NAME'),
        "key_access_service_account_email": config.get('SECUNDUS','SECUNDUS_KEY_ACCESS_SERVICE_ACCOUNT_EMAIL'),
        "wip_provider_name": config.get('SECUNDUS','SECUNDUS_WIP_PROVIDER_NAME'),
    }
    return read_from_bucket(secundus_table_info)


def main():
    """ write computed Items out.
    """

    primus_output = read_in_primus_table()

    secundus_output = read_in_secundus_table()

    primus_total = 0
    secundus_total = 0
    for sublist in primus_output:
      for item in sublist:
        primus_total += int(item)
    print(f"Primus Total: {primus_total}")

    for sublist in secundus_output:
      for item in sublist:
        secundus_total += int(item)
    print(f"Secondus Total: {secundus_total}")
    total = secundus_total + primus_total
    print(f"Total: {total}")
    data = [
        ["Grand Total"],
        [total]
    ]
    blob_name = "result.csv"
    result_bucket = config.get('SECUNDUS','SECUNDUS_RESULT_STORAGE_BUCKET')
    storage_client = storage.Client()
    bucket = storage_client.bucket(result_bucket)
    blob = bucket.blob(blob_name)
    # Write data to a string buffer in CSV format
    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerows(data)

    # Upload the CSV data from the buffer to GCS
    blob.upload_from_string(csv_buffer.getvalue())
    print(f"CSV file written to gs://{result_bucket}/{blob_name}")
    return total

if __name__ == "__main__":
    main()