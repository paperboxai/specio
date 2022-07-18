# This version is replaced during release process.
__version__ = '2022.0.dev1'

from .converters import openapi3_to_espv2_swagger_2
from .enums import SpecType
from .spec import OpenAPISpecification, Specification
from .utils import yamldumper


def resolve_from_file(spec_file: str, from_type: SpecType) -> Specification:
    """
    TBA
    """
    if from_type == SpecType.OpenAPI3_0:
        spec = OpenAPISpecification.from_file(spec_file)
    else:
        raise NotImplementedError(f'Conversion from {from_type} is not implemented.')

    return spec


def convert_from_file(spec_file: str, from_type: SpecType, to_type: SpecType) -> Specification:
    """
    TBA
    """
    if from_type == SpecType.OpenAPI3_0:
        spec = OpenAPISpecification.from_file(spec_file)
    else:
        raise NotImplementedError(f'Conversion from {from_type} is not implemented.')

    if to_type == SpecType.Swagger2_0:
        spec_out = openapi3_to_espv2_swagger_2.Converter.from_specification(spec)
    else:
        raise NotImplementedError(f"Conversion to {to_type} is not implemented yet.")

    return spec_out


def convert_from_to_file(
        spec_file: str, spec_file_out: str, from_type: SpecType, to_type: SpecType):
    """
    TBA
    """
    spec_out = convert_from_file(spec_file, from_type, to_type)

    with open(spec_file_out, 'w') as f:
        f.write(yamldumper(spec_out.spec))
