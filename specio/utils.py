"""
This module provides general utility functions used within Connexion.
"""

import functools

import yaml


def deep_get(obj, keys):
    """
    Recurses through a nested object get a leaf value.

    There are cases where the use of inheritance or polymorphism-- the use of allOf or
    oneOf keywords-- will cause the obj to be a list. In this case the keys will
    contain one or more strings containing integers.

    :type obj: list or dict
    :type keys: list of strings
    """
    if not keys:
        return obj

    if isinstance(obj, list):
        return deep_get(obj[int(keys[0])], keys[1:])
    else:
        return deep_get(obj[keys[0]], keys[1:])


def is_nullable(param_def):
    return (
        param_def.get('schema', param_def).get('nullable', False) or
        param_def.get('x-nullable', False)  # swagger2
    )


def is_null(value):
    if hasattr(value, 'strip') and value.strip() in ['null', 'None']:
        return True

    if value is None:
        return True

    return False


def is_json_mimetype(mimetype):
    """
    :type mimetype: str
    :rtype: bool
    """
    maintype, subtype = mimetype.split('/')  # type: str, str
    return maintype == 'application' and (subtype == 'json' or subtype.endswith('+json'))


def yamldumper(openapi):
    """
    Returns a nicely-formatted yaml spec.
    :param openapi: a spec dictionary.
    :return: a nicely-formatted, serialized yaml spec.
    """
    def should_use_block(value):
        char_list = (
            "\u000a"  # line feed
            "\u000d"  # carriage return
            "\u001c"  # file separator
            "\u001d"  # group separator
            "\u001e"  # record separator
            "\u0085"  # next line
            "\u2028"  # line separator
            "\u2029"  # paragraph separator
        )
        for c in char_list:
            if c in value:
                return True
        return False

    def my_represent_scalar(self, tag, value, style=None):
        if should_use_block(value):
            style = '|'
        else:
            style = self.default_style

        node = yaml.representer.ScalarNode(tag, value, style=style)
        if self.alias_key is not None:
            self.represented_objects[self.alias_key] = node
        return node

    class NoAnchorDumper(yaml.dumper.SafeDumper):
        """A yaml Dumper that does not replace duplicate entries
           with yaml anchors.
        """

        def ignore_aliases(self, *args):
            return True

    # Dump long lines as "|".
    yaml.representer.SafeRepresenter.represent_scalar = my_represent_scalar

    return yaml.dump(openapi, allow_unicode=True, Dumper=NoAnchorDumper)


def not_installed_error(exc):  # pragma: no cover
    """Raises the ImportError when the module/object is actually called."""

    def _required_lib(exc, *args, **kwargs):
        raise exc

    return functools.partial(_required_lib, exc)
