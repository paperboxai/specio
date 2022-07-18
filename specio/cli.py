import logging
from os import path
import sys
import specio

import click

from clickclick import AliasedGroup
from .enums import SpecType

from .spec import OpenAPISpecification
from .utils import yamldumper
from .converters import openapi3_to_espv2_swagger_2

logger = logging.getLogger("specio.cli")

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo(f'Specio {specio.__version__}')
    ctx.exit()


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False,
              is_eager=True, help='Print the current version number and exit.')
def main():
    pass


@main.command()
@click.argument('spec_file')
@click.argument('spec_file_out')
@click.option('--from-type', type=click.Choice([x.value for x in SpecType]),
              required=True, help='The type to convert from.')
@click.option('--to-type', type=click.Choice([x.value for x in SpecType]),
              required=True, help='The type to convert to.')
def convert(spec_file, spec_file_out, from_type: str, to_type: str):
    """
    TBA
    """
    try:
        from_ = SpecType(from_type)
    except AttributeError:
        raise NotImplementedError(f'Conversion from {from_type} is not implemented.')

    try:
        to_ = SpecType(to_type)
    except AttributeError:
        raise NotImplementedError(f"Conversion to {to_type} is not implemented yet.")

    specio.convert_from_to_file(spec_file, spec_file_out, from_, to_)
