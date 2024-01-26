#!/usr/bin/env python3

import hashlib
import os
import re
import subprocess

import requests


TOKEN = os.environ["TOKEN"]
ARMORED_PUBLIC_KEY = os.environ["GPG_PUBLIC_KEY"]
VERSION = os.environ["VERSION"].lstrip("v")

DIST_FILES = "./dist"
ORG_NAME = "captivateiq"
PROVIDER_NAME = "postgresql"
TIMEOUT = 30
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/vnd.api+json"
}


def generate_version_payload(version, key_id):
    return {
        "data": {
            "type": "registry-provider-versions",
            "attributes": {
                "version": version,
                "key-id": key_id,
                "protocols": ["5.0"]
            }
        }
    }


def generate_platform_payload(filename):
    with open(f"./dist/{filename}", "rb") as f:
        dist_bytes = f.read()
        shasum = hashlib.sha256(dist_bytes).hexdigest()
    re_pat = r"([a-zA-Z-]*)_([0-9A-Za-z.-]*)_(.*)_(.*).zip"
    match = re.match(re_pat, string=filename)
    groups = match.groups() if match else []
    return {
        "data": {
            "type": "registry-provider-version-platforms",
            "attributes": {
                "os": groups[2],
                "arch": groups[3],
                "shasum": shasum,
                "filename": filename
            }
        }
    }


def get_or_create_provider(provider_name, org_name):
    print(f"Org name: {org_name}, provider name: {provider_name}")
    provider_payload = {
        "data": {
            "type": "registry-providers",
            "attributes": {
                "name": provider_name,
                "namespace": org_name,
                "registry-name": "private"
            }
        }
    }

    r = requests.post(
        url=f"https://app.terraform.io/api/v2/organizations/{org_name}/registry-providers",
        json=provider_payload,
        headers=HEADERS,
        timeout=TIMEOUT
    )

    if r.status_code == 422:
        print("Provider already exists!")
        return True
    elif r.status_code == 201:
        print("Provider created!")
        return True
    print("Something bad happened")
    print("Status code", r.status_code)
    return False


def get_or_create_gpg_key(org_name, public_key):
    print("Processing public key...")
    gpg_key_payload = {
        "data": {
            "type": "gpg-keys",
            "attributes": {
                "namespace": org_name,
                "ascii-armor": public_key
            }
        }
    }
    r = requests.post(
        url="https://app.terraform.io/api/registry/private/v2/gpg-keys",
        json=gpg_key_payload,
        headers=HEADERS,
        timeout=TIMEOUT
    )
    if r.status_code == 400:
        print("GPG already created!")
        print("Moving forward and fetching current gpg key id")
        r = requests.get(
            url=f"https://app.terraform.io/api/registry/private/v2/gpg-keys?filter%5Bnamespace%5D={org_name}",
            headers=HEADERS,
            timeout=TIMEOUT
        )
        return r.json()["data"][0]["attributes"]["key-id"]
    elif r.status_code == 201:
        print("GPG created!")
        return r.json()["data"]["attributes"]["key-id"]
    print("Something bad happened")
    print("Status code", r.status_code)
    return None


def get_or_create_provider_version(org_name, provider_name, version, key_id):
    version_payload = generate_version_payload(version, key_id)
    r = requests.post(
        url=f"https://app.terraform.io/api/v2/organizations/{org_name}/registry-providers/private/{org_name}/{provider_name}/versions",
        json=version_payload,
        headers=HEADERS,
        timeout=TIMEOUT
    )
    if r.status_code == 422:
        print("Version already created!")
        print("Moving forward and fetching version")
        r = requests.get(
            url=f"https://app.terraform.io/api/v2/organizations/{org_name}/registry-providers/private/{org_name}/{provider_name}/versions/{version}",
            headers=HEADERS,
            timeout=TIMEOUT
        )
        return r.json()["data"]
    elif r.status_code == 201:
        print("Provider version created!")
        return r.json()["data"]
    print("Something bad happened")
    print("Status code", r.status_code)
    return None


def upload_sha_sums(provider_details):
    dist_files = os.listdir(DIST_FILES)
    links = provider_details["links"]

    shasum_file, shasum_sig_file = "", ""
    for file_ in dist_files:
        if file_.endswith("SHA256SUMS"):
            shasum_file = file_
        elif file_.endswith("SHA256SUMS.sig"):
            shasum_sig_file = file_

    if not provider_details["attributes"]["shasums-uploaded"]:
        r = requests.post(
            files={'file': open(f".{DIST_FILES}/{shasum_file}", "r")},
            url=links["shasums-upload"],
            timeout=TIMEOUT
        )
        if r.status_code != 201:
            print("Something bad happened")
            print("Status code", r.status_code)
            return False

    if not provider_details["attributes"]["shasums-sig-uploaded"]:
        r = requests.post(
            files={'file': open(f"{DIST_FILES}/{shasum_sig_file}", "r")},
            url=links["shasums-sig-upload"],
            timeout=TIMEOUT
        )
        if r.status_code != 201:
            print("Something bad happened")
            print("Status code", r.status_code)
            return False

    return True


def create_and_upload_platform_files(org_name, provider_name, version):
    dist_files = os.listdir(DIST_FILES)
    for file_ in dist_files:
        if not file_.endswith(".zip"):
            continue
        platform = generate_platform_payload(file_)
        r = requests.post(
            url=f"https://app.terraform.io/api/v2/organizations/{org_name}/registry-providers/private/{org_name}/{provider_name}/versions/{version}/platforms",
            json=platform,
            headers=HEADERS,
            timeout=TIMEOUT
        )
        if r.status_code == 422:
            print("Platform already created!")
            print("Fetching platform details")
            r = requests.get(
                url=f"https://app.terraform.io/api/v2/organizations/{org_name}/registry-providers/private/{org_name}/{provider_name}/versions/{VERSION}/platforms/{platform['data']['attributes']['os']}/{platform['data']['attributes']['arch']}",
                headers=HEADERS,
                timeout=TIMEOUT
            )
        if not r.json()["data"]["attributes"]["provider-binary-uploaded"]:
            print("Binary not yet uploaded! Uploading...")
            links = r.json()["data"]["links"]
            subprocess.run(["curl", "-T", f"./dist/{file_}", links['provider-binary-upload']])
            # resp = requests.post(
            #     files={'file': open(f"./dist/{file_}", "rb")},
            #     url=links["provider-binary-upload"],
            #     timeout=TIMEOUT
            # )
        else:
            print("Binary already uploaded! Moving on...")


if __name__ == "__main__":
    if not get_or_create_provider(PROVIDER_NAME, ORG_NAME):
        exit(1)
    key_id = get_or_create_gpg_key(ORG_NAME, ARMORED_PUBLIC_KEY)
    if not key_id:
        exit(2)
    provider_details = get_or_create_provider_version(ORG_NAME, PROVIDER_NAME, VERSION, key_id)
    if not provider_details:
        exit(3)
    if not upload_sha_sums(provider_details):
        exit(4)
    create_and_upload_platform_files(ORG_NAME, PROVIDER_NAME, VERSION)
