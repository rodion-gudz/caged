""" PyPI Package Malware Scanner

CLI command that scans a PyPI package version for user-specified malware flags.
Includes rules based on package registry metadata and source code analysis.
"""
import logging
import os
import sys
from typing import Iterable, Optional, cast

import rich_click as click
import rich
from pip._internal.cli.main import main as pip_main
from prettytable import PrettyTable
from rich.logging import RichHandler

from cagged.analyzer.analyzer import SEMGREP_RULE_NAMES
from cagged.analyzer.metadata import get_metadata_detectors
from cagged.analyzer.sourcecode import SOURCECODE_RULES
from cagged.dynamic.analyze import run_analysis
from cagged.ecosystems import ECOSYSTEM
from cagged.misc import console, console_without_time
from cagged.reporters.sarif import report_verify_sarif
from cagged.scanners import get_scanner
from cagged.scanners.scanner import PackageScanner
from cagged.utils.package_info import get_package_info

ALL_RULES = (
    set(get_metadata_detectors(ECOSYSTEM.NPM).keys())
    | set(get_metadata_detectors(ECOSYSTEM.PYPI).keys())
    | SEMGREP_RULE_NAMES
)
EXIT_CODE_ISSUES_FOUND = 1

AVAILABLE_LOG_LEVELS = {logging.DEBUG, logging.INFO, logging.WARN, logging.ERROR}
AVAILABLE_LOG_LEVELS_NAMES = list(
    map(lambda level: logging.getLevelName(level), AVAILABLE_LOG_LEVELS)
)

FORMAT = "%(message)s"
logging.basicConfig(
    level="INFO", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(show_path=False)]
)

log = logging.getLogger("rich")


def common_options(fn):
    fn = click.option(
        "--exit-non-zero-on-finding",
        default=False,
        is_flag=True,
        help="Exit with a non-zero status code if at least one issue is identified",
    )(fn)
    fn = click.option(
        "-r",
        "--rules",
        multiple=True,
        type=click.Choice(ALL_RULES, case_sensitive=False),
    )(fn)
    fn = click.option(
        "-x",
        "--exclude-rules",
        multiple=True,
        type=click.Choice(ALL_RULES, case_sensitive=False),
    )(fn)
    fn = click.argument("target")(fn)
    return fn


def verify_options(fn):
    fn = click.option(
        "--output-format",
        default=None,
        type=click.Choice(["json", "sarif"], case_sensitive=False),
    )(fn)
    return fn


def scan_options(fn):
    fn = click.option(
        "--output-format",
        default=None,
        type=click.Choice(["json"], case_sensitive=False),
    )(fn)
    fn = click.option(
        "-v", "--version", default=None, help="Specify a version to scan"
    )(fn)
    return fn


def logging_options(fn):
    fn = click.option(
        "--log-level",
        default="INFO",
        type=click.Choice(AVAILABLE_LOG_LEVELS_NAMES, case_sensitive=False),
    )(fn)
    return fn


@click.group
@logging_options
def cli(log_level):
    """
    caged is a tool for safely installing packages from different repositories.

    PyPI and NPM are supported at the moment.

    Example: caged pip install requests

    Use --help for the detail of all commands and subcommands
    """
    logger = logging.getLogger("caged")
    logger.setLevel(logging.getLevelName(log_level))
    stdoutHandler = logging.StreamHandler(stream=sys.stdout)
    stdoutHandler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(stdoutHandler)
    pass


def _get_rule_pram(rules, exclude_rules):
    rule_param = None
    if len(rules) > 0:
        rule_param = rules
    if len(exclude_rules) > 0:
        rule_param = ALL_RULES - set(exclude_rules)
        if len(rules) > 0:
            print("--rules and --exclude-rules cannot be used together")
            exit(1)
    return rule_param


def _verify(
    path, rules, exclude_rules, output_format, exit_non_zero_on_finding, ecosystem
):
    """Verify a requirements.txt file

    Args:
        path (str): path to requirements.txt file
    """
    return_value = None
    rule_param = _get_rule_pram(rules, exclude_rules)
    scanner = get_scanner(ecosystem, True)
    if scanner is None:
        sys.stderr.write(f"Command verify is not supported for ecosystem {ecosystem}")
        exit(1)

    def display_result(result: dict) -> None:
        identifier = (
            result["dependency"]
            if result["version"] is None
            else f"{result['dependency']} version {result['version']}"
        )
        if output_format is None:
            print_scan_results(result.get("result"), identifier)

        if len(result.get("errors", [])) > 0:
            print_errors(result.get("error"), identifier)

    results = scanner.scan_local(path, rule_param, display_result)
    if output_format == "json":
        import json as js

        return_value = js.dumps(results)

    if output_format == "sarif":
        return_value = report_verify_sarif(path, list(ALL_RULES), results, ecosystem)

    if output_format is not None:
        print(return_value)

    if exit_non_zero_on_finding:
        exit_with_status_code(results)

    return return_value


def is_local_target(identifier: str) -> bool:
    """
    @param identifier:  The name/path of the package as passed to "caged ecosystem scan"
    @return:            Whether the identifier should be consider a local path
    """
    if (
        identifier.startswith("/")
        or identifier.startswith("./")
        or identifier.startswith("../")
    ):
        return True

    if identifier == ".":
        return True

    if (
        identifier.endswith(".tar.gz")
        or identifier.endswith(".zip")
        or identifier.endswith(".whl")
    ):
        return os.path.exists(identifier)

    return False


def is_verified_package(result: dict) -> bool:
    """
    @param result:  The result of a scan
    @return:        Whether the result is a verified package
    """
    return not result.get("issues")


def install_pypi_package(zip_path: str, pip_args: Iterable) -> None:
    """
    @param zip_path:    The path to the zip file
    @param pip_args:    Additional arguments to pass to pip
    """
    log.debug(f"Installing package from {zip_path}")
    pip_main(["install", zip_path, *pip_args])


def _scan(
    identifier,
    version,
    rules,
    exclude_rules,
    output_format,
    exit_non_zero_on_finding,
    ecosystem: ECOSYSTEM,
    install_package=False,
    pip_args=None,
):
    """Scan a package

    Args:
        identifier (str): name or path to the package
        version (str): version of the package (ex. 1.0.0), defaults to most recent
        rules (list[str]): specific rules to run, defaults to all
    """

    if not is_local_target(identifier):
        package_info = get_package_info(identifier)

        console_without_time.rule(f"[bold]Package information[/bold]")

        console_without_time.log(
            f"[bold][green]{identifier}[/green][/bold] – [italic]{package_info['info']['summary']}[/italic]",
            justify="center",
        )
        console_without_time.log(
            f"[bold]Version[/bold] – {package_info['info']['version']}",
            justify="center",
        )
        console_without_time.log(
            f"[bold]Author[/bold] – {package_info['info']['author']}", justify="center"
        )

        console.line()

    rule_param = _get_rule_pram(rules, exclude_rules)
    scanner = cast(Optional[PackageScanner], get_scanner(ecosystem, False))
    if scanner is None:
        sys.stderr.write(f"Command scan is not supported for ecosystem {ecosystem}")
        exit(1)

    results = {}
    if is_local_target(identifier):
        log.debug(
            f"Considering that '{identifier}' is a local target, scanning filesystem"
        )
        results, zip_path = scanner.scan_local(identifier, rule_param)
    else:
        log.debug(f"Considering that '{identifier}' is a remote target")
        try:
            results, zip_path = scanner.scan_remote(identifier, version, rule_param)
        except Exception as e:
            sys.stderr.write("\n")
            sys.stderr.write(str(e))
            sys.exit()

    if output_format == "json":
        import json as js

        print(js.dumps(results))
    else:
        print_scan_results(results, identifier)

    static_verdict = is_verified_package(results)

    if static_verdict:
        dynamic_verdict = not run_analysis(
            ecosystem="pypi",
            package=identifier,
            package_path=zip_path,
        )

        if install_package:
            if dynamic_verdict:
                console.log(
                    f"🟢 Considering that [bold]'{identifier}'[/bold] is a [green]valid[/green] package. [bold]Starting installation process[/bold]",
                    emoji=True,
                )
                print()
                install_pypi_package(zip_path, pip_args)
            else:
                console.log(
                    f"🔴 Considering that [bold]'{identifier}'[/bold] is a [red]malicious[/red] package. [bold]Installation [red]aborted[/red][/bold]",
                    emoji=True,
                )
    else:
        console.log(
            f"🔴 Considering that [bold]'{identifier}'[/bold] is a [red]malicious[/red] package. [bold]Installation [red]aborted[/red][/bold]",
            emoji=True,
        )

    if exit_non_zero_on_finding:
        exit_with_status_code(results)


def _list_rules(ecosystem):
    table = PrettyTable()
    table.align = "l"
    table.field_names = ["Rule type", "Rule name", "Description"]

    for rule in SOURCECODE_RULES[ecosystem]:
        table.add_row(
            ["Source code", rule["id"], rule.get("metadata", {}).get("description")]
        )

    metadata_rules = get_metadata_detectors(ecosystem)
    for ruleName in metadata_rules:
        rule = metadata_rules[ruleName]
        table.add_row(["Package metadata", rule.get_name(), rule.get_description()])

    print(table)


@cli.group
def npm(**kwargs):
    """Install npm package"""
    pass


@cli.group
def pip(**kwargs):
    """Install PyPI package"""
    pass


@npm.command("scan")
@common_options
@scan_options
def scan_npm(
    target, version, rules, exclude_rules, output_format, exit_non_zero_on_finding
):
    """Scan a given npm package"""
    return _scan(
        target,
        version,
        rules,
        exclude_rules,
        output_format,
        exit_non_zero_on_finding,
        ECOSYSTEM.NPM,
    )


@npm.command("verify")
@common_options
@verify_options
def verify_npm(target, rules, exclude_rules, output_format, exit_non_zero_on_finding):
    """Verify a given npm project"""
    return _verify(
        target,
        rules,
        exclude_rules,
        output_format,
        exit_non_zero_on_finding,
        ECOSYSTEM.NPM,
    )


@pip.command(
    "install",
    context_settings=dict(
        ignore_unknown_options=True,
    ),
)
@common_options
@scan_options
@click.argument("pip_args", nargs=-1, type=click.UNPROCESSED)
def install_pypi(
    target,
    version,
    rules,
    exclude_rules,
    output_format,
    exit_non_zero_on_finding,
    pip_args,
):
    """Scan and install a given PyPI package"""
    return _scan(
        target,
        version,
        rules,
        exclude_rules,
        output_format,
        exit_non_zero_on_finding,
        ECOSYSTEM.PYPI,
        install_package=True,
        pip_args=pip_args,
    )


@pip.command("scan")
@common_options
@scan_options
def scan_pypi(
    target, version, rules, exclude_rules, output_format, exit_non_zero_on_finding
):
    """Scan a given PyPI package"""
    return _scan(
        target,
        version,
        rules,
        exclude_rules,
        output_format,
        exit_non_zero_on_finding,
        ECOSYSTEM.PYPI,
    )


@pip.command("verify")
@common_options
@verify_options
def verify_pypi(target, rules, exclude_rules, output_format, exit_non_zero_on_finding):
    """Verify a given Pypi project"""
    return _verify(
        target,
        rules,
        exclude_rules,
        output_format,
        exit_non_zero_on_finding,
        ECOSYSTEM.PYPI,
    )


@pip.command("list-rules")
def list_rules_pypi():
    """Print available rules for PyPI"""
    return _list_rules(ECOSYSTEM.PYPI)


@npm.command("list-rules")
def list_rules_npm():
    """Print available rules for npm"""
    return _list_rules(ECOSYSTEM.NPM)


def print_scan_results(results, identifier):
    num_issues = results.get("issues")
    errors = results.get("errors", [])

    if num_issues == 0:
        console.log(
            f"🟢 Found [green]0[/green] potentially malicious indicators scanning [bold][green]{identifier}[/green][/bold]",
            emoji=True,
        )
        console.line()
    else:
        console.log(
            f"🔴 Found [red]{num_issues}[/red] potentially malicious indicators scanning [bold][green]{identifier}[/green][/bold]",
            emoji=True,
        )

        findings = results.get("results", [])
        for finding in findings:
            description = findings[finding]
            if type(description) == str:
                console.log(f"[bold]{finding}[/bold]: {description}")
                console.line()
            elif type(description) == list:
                source_code_findings = description
                console.log(
                    f"[bold][red]{finding}[/red][/bold]: found [red]{len(source_code_findings)}[/red] source code matches"
                )
                for finding in source_code_findings:
                    console.log(
                        f"  * {finding['message']} at {finding['location']} \n      {format_code_line_for_output(finding['code'])}"
                    )
                console.line()
                print()

    if len(errors) > 0:
        print_errors(errors, identifier)
        print("\n")


def print_errors(errors, identifier):
    console.log(
        f"[yellow]Some rules failed to run while scanning [bold][green]{identifier}[/green][/bold]:[/yellow]"
    )
    console.line()
    for rule in errors:
        console.log(
            f"  * [bold][yellow]{rule}[/yellow][/bold]: [italic]{errors[rule]}[/italic]"
        )
    console.line()


def format_code_line_for_output(code):
    return "    " + code.strip().replace("\n", "\n    ").replace("\t", "  ")


def exit_with_status_code(results):
    num_issues = results.get("issues", 0)
    if num_issues > 0:
        exit(EXIT_CODE_ISSUES_FOUND)
