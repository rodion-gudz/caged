import logging

import requests

log = logging.getLogger("caged")


def get_package_info(name: str) -> dict:
    """Gets metadata and other information about package

    Args:
        name (str): name of the package

    Raises:
        Exception: "Received status code: " + str(response.status_code) + " from PyPI"
        Exception: "Error retrieving package: " + data["message"]

    Returns:
        json: package attributes and values
    """

    url = "https://pypi.org/pypi/%s/json" % (name,)
    log.debug(f"Retrieving PyPI package metadata from {url}")
    response = requests.get(url)

    if response.status_code != 200:
        raise Exception(
            "Received status code: " + str(response.status_code) + " from PyPI"
        )

    data = response.json()

    if "message" in data:
        raise Exception("Error retrieving package: " + data["message"])

    return data
