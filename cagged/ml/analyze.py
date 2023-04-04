import os
import re

import joblib
import pandas as pd
import rich
from rich.table import Table


def vectorize_package_info(package_info):
    analysis = package_info["Analysis"]

    if analysis.get("import") is None:
        return None
    import_analysis = analysis["import"]
    import_analysis_files = import_analysis["Files"]
    import_analysis_sockets = import_analysis["Sockets"]
    import_analysis_commands = import_analysis["Commands"]
    import_analysis_dns = import_analysis["DNS"]

    num_import_sockets = 0
    num_import_web_sockets = 0
    num_import_dns_sockets = 0
    num_import_ftp_sockets = 0
    num_import_zero_sockets = 0
    num_import_other_sockets = 0
    num_import_local_sockets = 0
    if import_analysis_sockets is not None:
        for socket in import_analysis_sockets:
            if socket["Port"] == 80 or socket["Port"] == 443:
                num_import_web_sockets += 1
            elif socket["Port"] == 53:
                num_import_dns_sockets += 1
            elif socket["Port"] == 21:
                num_import_ftp_sockets += 1
            elif socket["Port"] == 0:
                num_import_zero_sockets += 1
            else:
                num_import_other_sockets += 1

            if socket["Address"] == "::1" or socket["Address"] == "127.0.0.1":
                num_import_local_sockets += 1

    num_import_commands = (
        0 if import_analysis_commands is None else len(import_analysis_commands)
    )
    num_import_dns_records = (
        0 if import_analysis_dns is None else len(import_analysis_dns)
    )
    num_import_files = (
        0 if import_analysis_files is None else len(import_analysis_files)
    )
    num_import_read_files = 0
    num_import_write_files = 0
    num_import_delete_files = 0
    if import_analysis_files:
        for file in import_analysis_files:
            if file["Read"]:
                num_import_read_files += 1
            if file["Write"]:
                num_import_write_files += 1
            if file["Delete"]:
                num_import_delete_files += 1

    return {
        "importDNS": num_import_dns_records,
        "importCommands": num_import_commands,
        "importSockets": num_import_sockets,
        "importWebSockets": num_import_web_sockets,
        "importDNSSockets": num_import_dns_sockets,
        "importFTPSockets": num_import_ftp_sockets,
        "importZeroSockets": num_import_zero_sockets,
        "importOtherSockets": num_import_other_sockets,
        "importLocalSockets": num_import_local_sockets,
        "importFiles": num_import_files,
        "importReadFiles": num_import_read_files,
        "importWriteFiles": num_import_write_files,
        "importDeleteFiles": num_import_delete_files,
    }


def analyze_ml(package_info: dict) -> bool:
    """
    Analyze a package using a machine learning model and predict if it is malicious or not.
    :param package_info:
    :return: bool (True if malicious, False if not)
    """
    vectorized = vectorize_package_info(package_info)

    print()
    table = Table(
        *[
            "DNS Records",
            "Commands",
            "Sockets",
            "Web Sockets",
            "DNS Sockets",
            "FTP Sockets",
            "Zero Sockets",
            "Other Sockets",
            "Local Sockets",
            "Files",
            "Read Files",
            "Write Files",
            "Delete Files",
        ],
        title="Source code analysis",
    )

    table.add_row(*[str(value) for value in vectorized.values()])

    rich.print(table)
    print()

    df = pd.DataFrame([vectorized])

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "model.joblib"), "rb") as r:
        model = joblib.load(r)

    prediction = model.predict(df)

    return prediction[0]
