import json
import os
from typing import Dict

import docker

from cagged.misc import console
from cagged.ml.analyze import analyze_ml


def run_analysis(
    ecosystem: str,
    package: str,
    package_path: str = "",
    dry_run: bool = False,
    fully_offline: bool = False,
) -> bool:
    caged_results_dir = "/tmp/caged"
    results_dir = f"{caged_results_dir}/results"

    docker_opts = ["run"]
    docker_mounts = [
        "-v",
        "/var/lib/containers:/var/lib/containers",
        "-v",
        f"{results_dir}:/results",
    ]
    analysis_image = "ghcr.io/rodion-gudz/analysis"
    analysis_args = [
        "analyze",
        "-upload",
        "file:///results/",
        "-ecosystem",
        ecosystem,
        "-package",
        package,
    ]

    package_path = os.path.realpath(os.path.expanduser(package_path))
    mounted_pkg_path = f"/{os.path.basename(package_path)}"
    docker_mounts += ["-v", f"{package_path}:{mounted_pkg_path}"]
    analysis_args += ["-local", mounted_pkg_path]

    if fully_offline:
        docker_opts += ["--network", "none"]
    if dry_run:
        command = {
            "command": f"docker {' '.join(docker_opts)} {' '.join(docker_mounts)} {analysis_image} {' '.join(analysis_args)}"
        }
        print(command)
        return command

    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    docker_client = docker.from_env()

    container = docker_client.containers.run(
        image=analysis_image,
        command=" ".join(analysis_args),
        detach=True,
        remove=True,
        cgroupns="host",
        privileged=True,
        tty=True,
        volumes={
            results_dir: {"bind": "/results", "mode": "rw"},
            package_path: {"bind": mounted_pkg_path, "mode": "rw"},
        },
    )

    output = container.attach(stdout=True, stream=True, logs=True)
    for line in output:
        parts = line.decode().strip().split(maxsplit=3)
        if len(parts) == 4:
            time, level, file, message = parts
            if level == "INFO" and 'static' not in message.lower() and len(message.split()) > 1:
                console.log(message.split("{")[0].strip().capitalize())

    with open("/tmp/caged/results/results.json") as f:
        analysis_output = json.load(f)

    print()

    console.log(f"💬 Analyzing results using Machine Learning ...", emoji=True)

    return analyze_ml(analysis_output)
