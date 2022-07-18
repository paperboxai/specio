"""
This module defines Exception classes used by Connexion to generate a proper response.
"""

from jsonschema.exceptions import ValidationError


class ConnexionException(Exception):
    pass


class InvalidSpecification(ConnexionException, ValidationError):
    pass
