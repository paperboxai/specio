import logging
from os import path
import sys
import specio

import click

from clickclick import AliasedGroup
from .enums import SpecType

from .spec import OpenAPISpecification, Swagger2Specification
from .utils import yamldumper
from .converters import openapi3_to_espv2_swagger_2

logger = logging.getLogger("specio.cli")

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"Specio {specio.__version__}")
    ctx.exit()


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option(
    "-V",
    "--version",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="Print the current version number and exit.",
)
def main():
    pass


@main.command()
@click.argument("spec_file")
@click.argument("spec_file_out")
@click.option(
    "--from-type",
    type=click.Choice([x.value for x in SpecType]),
    required=True,
    help="The type to convert from.",
)
@click.option(
    "--to-type",
    type=click.Choice([x.value for x in SpecType]),
    required=True,
    help="The type to convert to.",
)
def convert(spec_file, spec_file_out, from_type: str, to_type: str):
    """
    TBA
    """
    try:
        from_ = SpecType(from_type)
    except AttributeError:
        raise NotImplementedError(f"Conversion from {from_type} is not implemented.")

    try:
        to_ = SpecType(to_type)
    except AttributeError:
        raise NotImplementedError(f"Conversion to {to_type} is not implemented yet.")

    specio.convert_from_to_file(spec_file, spec_file_out, from_, to_)


@main.command()
@click.argument("spec_file")
@click.option(
    "--type",
    type=click.Choice([x.value for x in SpecType]),
    required=True,
    help="The type to convert from.",
)
def validate(spec_file, type: str):
    """
    TBA
    """
    try:
        type_ = SpecType(type)
    except AttributeError:
        raise NotImplementedError(f"Validation for {type} is not implemented.")

    if type_ == SpecType.OpenAPI3_0:
        OpenAPISpecification.from_file(spec_file)
    elif type_ == SpecType.Swagger2_0:
        Swagger2Specification.from_file(spec_file)
    else:
        raise NotImplementedError(f"Validation for {type_} is not implemented yet.")


@main.command()
@click.argument("spec_file")
@click.argument("spec_file_out")
@click.option(
    "--type",
    type=click.Choice([x.value for x in SpecType]),
    required=True,
    help="The type to convert from.",
)
def resolve(spec_file, spec_file_out, type: str):
    """
    TBA
    """
    try:
        type_ = SpecType(type)
    except AttributeError:
        raise NotImplementedError(f"Validation for {type} is not implemented.")

    if type_ == SpecType.OpenAPI3_0:
        specio.resolve_from_to_file(spec_file, spec_file_out, type_)
    elif type_ == SpecType.Swagger2_0:
        specio.resolve_from_to_file(spec_file, spec_file_out, type_)
    else:
        raise NotImplementedError(f"Validation for {type_} is not implemented yet.")
