import os
import typing

from cagged.analyzer.analyzer import Analyzer
from cagged.ecosystems import ECOSYSTEM
from cagged.scanners.scanner import PackageScanner
from cagged.utils.package_info import get_package_info


class PypiPackageScanner(PackageScanner):
    def __init__(self) -> None:
        super().__init__(Analyzer(ECOSYSTEM.PYPI))

    def download_and_get_package_info(
        self, directory: str, package_name: str, version=None
    ) -> typing.Tuple[dict, str, str]:
        zip_path, extract_dir = self.download_package(package_name, directory, version)
        return get_package_info(package_name), zip_path, extract_dir

    def download_package(self, package_name, directory, version=None) -> (str, str):
        """Downloads the PyPI distribution for a given package and version

        Args:
            package_name (str): name of the package
            directory (str): directory to download package to
            version (str): version of the package

        Raises:
            Exception: "Received status code: " + <not 200> + " from PyPI"
            Exception: "Version " + version + " for package " + package_name + " doesn't exist."
            Exception: "Compressed file for package does not exist."
            Exception: "Error retrieving package: " + <error message>
        Returns:
            Path where the package was extracted
        """

        data = get_package_info(package_name)
        releases = data["releases"]

        if version is None:
            version = data["info"]["version"]

        if version in releases:
            files = releases[version]

            url = None
            file_extension = None

            for file in files:

                if file["filename"].endswith(".tar.gz"):
                    url = file["url"]
                    file_extension = ".tar.gz"

                if (
                    file["filename"].endswith(".egg")
                    or file["filename"].endswith(".whl")
                    or file["filename"].endswith(".zip")
                ):
                    url = file["url"]
                    file_extension = ".zip"

            if url and file_extension:

                zippath = os.path.join(directory, package_name + file_extension)
                unzippedpath = zippath.removesuffix(file_extension)

                self.download_compressed(url, zippath, unzippedpath)
                return zippath, unzippedpath
            else:
                raise Exception(
                    f"Compressed file for {package_name} does not exist on PyPI."
                )
        else:
            raise Exception(
                "Version "
                + version
                + " for package "
                + package_name
                + " doesn't exist."
            )
