from copy import deepcopy
import logging
from specio import utils
from specio.spec import OpenAPISpecification, Swagger2Specification
import urllib.parse

HTTP_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']
SCHEMA_PROPERTIES = [
    'format', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'minLength',
    'maxLength', 'multipleOf', 'minItems', 'maxItems', 'uniqueItems', 'minProperties',
    'maxProperties', 'additionalProperties', 'pattern', 'enum', 'default']
ARRAY_PROPERTIES = ['type', 'items']

SUPPORTED_MIME_TYPES = {
    "APPLICATION_X_WWW_URLENCODED": 'application/x-www-form-urlencoded',
    "MULTIPART_FORM_DATA": 'multipart/form-data'
}

logger = logging.getLogger('specio.converter')


class Converter():
    """
    Converts OpenAPI 3.0 spec to Swagger 2.0 spec.
    """

    @classmethod
    def from_dict(cls, spec: dict) -> dict:
        return cls.__convert(spec)

    @classmethod
    def from_specification(cls, spec: OpenAPISpecification) -> Swagger2Specification:
        return Swagger2Specification(cls.__convert(spec.spec))

    @classmethod
    def __convert(cls, spec: dict) -> dict:
        """
        Converts OpenAPI 3.0 spec to Swagger 2.0 spec.
        """
        logger.warn(
            'Converting to ESPv2 Swagger 2.0 will not keep your components intact and will resolve all $refs.')
        spec = deepcopy(spec)
        spec["swagger"] = '2.0'
        cls.__convert_infos(spec)
        cls.__convert_operations(spec)
        if spec.get('components') is not None:
            cls.__convert_security_definitions(spec)
            del spec['components']
        return spec

    @classmethod
    def __convert_infos(cls, spec: dict):
        """
        Converts the info section of the OpenAPI 3.0 spec to the info section of the Swagger 2.0 spec.
        """
        server = spec['servers'][0] if 'servers' in spec else None

        if server:
            server_url = server['url']
            variables = server.get('variables', {})
            if variables:
                for variable in variables:
                    server_url = server_url.replace('{' + variable + '}', variables[variable])
            spec['host'] = server_url
            spec['basePath'] = server['url'].split('/')[-1]

            url = urllib.parse.urlparse(server_url)
            if url.netloc is None:
                del spec['host']
            else:
                spec['host'] = url.netloc

            if url.scheme is None:
                del spec['schemes']
            else:
                spec['schemes'] = [url.scheme[
                    0: len(url.scheme) - 1]]  # strip off trailing colon

            spec['basePath'] = url.path
        spec.pop('servers', None)
        del spec['openapi']

    @classmethod
    def __convert_operations(cls, spec: dict):
        """
        Converts the operations section of the OpenAPI 3.0 spec to the operations section of the Swagger 2.0 spec.
        """
        for path in spec['paths']:
            cls.__convert_parameters(spec['paths'][path])  # converts common parameters
            for method in spec['paths'][path]:
                if method in HTTP_METHODS:
                    operation = spec['paths'][path][method]
                    cls.__convert_operation_parameters(operation)
                    cls.__convert_responses(operation)

    @classmethod
    def __convert_parameters(cls, operation: dict):
        """
        Converts the parameters section of the OpenAPI 3.0 spec to the parameters section of the Swagger 2.0 spec.
        """

        if 'parameters' not in operation:
            return

        for param in operation['parameters']:
            if param['in'] != 'body':
                cls.__copy_schema_properties(param, SCHEMA_PROPERTIES)
                cls.__copy_schema_properties(param, ARRAY_PROPERTIES)
                cls.__copy_schema_x_properties(param)

                param.pop("schema", None)
                param.pop("allowReserved", None)

                if param.get('example') is not None:
                    param['x-example'] = param['example']

                param.pop("example", None)

            if param.get('type') == 'array':
                style = 'simple'
                if param.get('style') is not None:
                    style = param['style']
                elif param.get('in') == 'query' or param.get('in') == 'cookie':
                    style = 'form'

                if (style == 'matrix'):
                    param['collectionFormat'] = None if param.get('explode', False) else 'csv'
                elif style == 'label':
                    param['collectionFormat'] = None
                elif style == 'simple':
                    param['collectionFormat'] = 'csv'
                elif style == 'spaceDelimited':
                    param['collectionFormat'] = 'ssv'
                elif style == 'pipeDelimited':
                    param['collectionFormat'] = 'pipes'
                elif style == 'deepOpbject':
                    param['collectionFormat'] = 'multi'
                elif style == 'form':
                    param['collectionFormat'] = 'csv' if not param.get(
                        'explode', False) else 'multi'
            param.pop("style", None)
            param.pop("explode", None)

    @classmethod
    def __copy_schema_properties(cls, param: dict, props: list):
        """
        Copies properties from the schema to the parameter.
        """
        if param.get('schema') is None:
            return

        for prop in props:

            if prop == 'additionalProperties':
                if isinstance(param['schema'].get(prop), bool):
                    continue

            if prop in param['schema']:
                param[prop] = param['schema'].get(prop)

    @classmethod
    def __copy_schema_x_properties(cls, param: dict):
        """
        Copies properties from the schema to the parameter.
        """
        if param.get('schema') is None:
            return

        for prop in param.get('schema'):
            if prop in param['schema'] and prop not in param and prop.startswith('x-'):
                param[prop] = param['schema'][prop]

    @classmethod
    def __convert_responses(cls, operation: dict):
        """
        """
        for code in operation['responses']:
            response = operation['responses'][code]
            if response.get('content'):
                any_schema = json_schema = None
                for media_range in response['content']:
                    # produces and examples only allow media types, not ranges
                    # use application/octet-stream as a catch-all type
                    media_type = media_range if '*' not in media_range else 'application/octet-stream'
                    if not operation.get('produces'):
                        operation['produces'] = [media_type]
                    elif (operation['produces'].index(media_type) < 0):
                        operation['produces'].append(media_type)

                    content = response['content'][media_range]

                    any_schema = any_schema if any_schema is not None else content['schema']
                    if not json_schema and utils.is_json_mimetype(media_type):
                        json_schema = content['schema']

                    if content.get('example') is not None:
                        response['examples'] = response.get('examples', {})
                        response['examples'][media_type] = response.get('examples', {})

                if any_schema is not None:
                    response['schema'] = json_schema if json_schema is not None else any_schema
                    cls.__convert_schema(response['schema'], 'response')

            headers = response.get('headers')
            if headers is not None:
                for header_name in headers:
                    header = headers[header_name]
                    # Headers should be converted like parameters.
                    if header['schema'] is not None:
                        header['type'] = header['schema'].get('type')
                        header['format'] = header['schema'].get('format')
                        header.pop("schema", None)

            response.pop("content", None)

    @classmethod
    def __convert_schema(cls, schema: dict, operation_direction: str):
        """
        Converts the schema section of the OpenAPI 3.0 spec to the schema section of the Swagger 2.0 spec.
        """
        if schema.get('oneOf') is not None:
            schema.pop("oneOf", None)
            schema.pop("discriminator", None)

        if schema.get('anyOf') is not None:
            schema.pop("anyOf", None)
            schema.pop("discriminator", None)

        if schema.get('allOf') is not None:
            for i in schema['allOf']:
                cls.__convert_schema(schema['allOf'][i], operation_direction)

        if schema.get('discriminator') is not None:
            if schema['discriminator'].get('mapping') is not None:
                cls.__convert_discriminator_mapping(schema, schema['discriminator']['mapping'])

            schema['discriminator'] = schema['discriminator'].get('propertyName')

        schema_type = schema.get('type')
        if schema_type == 'object':
            if schema.get('properties') is not None:
                for prop_name in schema['properties']:
                    if schema['properties'][prop_name].get(
                            'writeOnly', False) and operation_direction == 'response':
                        schema['properties'].pop(prop_name, None)
                    else:
                        cls.__convert_schema(schema['properties'][prop_name], operation_direction)
                        schema['properties'][prop_name].pop('writeOnly', None)

            if schema.get("additionalProperties") is not None and isinstance(
                    schema['additionalProperties'], dict):
                schema["additionalProperties"] = True

        elif schema_type == 'array':
            if schema.get('items') is not None:
                cls.__convert_schema(schema['items'], operation_direction)

        if schema.get('nullable') is not None:
            schema['x-nullable'] = True
            schema.pop("nullable", None)

        # OpenAPI 3 has boolean "deprecated" on Schema, OpenAPI 2 does not
        # Convert to x-deprecated for Autorest (and perhaps others)
        if schema.get('deprecated') is not None:
            # Move to x-deprecated, unless it is already undefined
            if schema.get('x-deprecated') is None:
                schema['x-deprecated'] = schema['deprecated']

            schema.pop("deprecated", None)

    @classmethod
    def __convert_discriminator_mapping(cls, schema: dict, mapping: dict):
        """
        Converts the discriminator mapping section of the OpenAPI 3.0 spec to the schema section of the Swagger 2.0 spec.
        """
        for payload in mapping:
            schema_name = mapping[payload]
            if not isinstance(schema_name, str):
                logger.warn(f"Ignoring {schema_name} for {payload} in discriminator.mapping.")
                continue

            # payload may be a schema name or JSON Reference string.
            # OAS3 spec limits schema names to ^[a-zA-Z0-9._-]+$
            # Note: Valid schema name could be JSON file name without extension.
            #       Prefer schema name, with file name as fallback.
            # Swagger Codegen + OpenAPI Generator extension
            # https: // github.com/swagger-api/swagger-codegen/pull/4252
            schema['x-discriminator-value'] = payload

            # AutoRest extension
            # https: // github.com/Azure/autorest/pull/474
            schema['x-ms-discriminator-value'] = payload

    @classmethod
    def __convert_security_definitions(cls, spec: dict):
        """
        Converts the security definitions section of the OpenAPI 3.0 spec to the security definitions section of the Swagger 2.0 spec.
        """
        if spec.get('components', {}).get('securitySchemes') is None:
            return
        security_definitions = spec['components']['securitySchemes']
        for secKey in security_definitions:
            security = security_definitions[secKey]
            if security.get('type') == 'http' and security.get('scheme') == 'basic':
                security['type'] = 'basic'
                security.pop("scheme", None)
            elif security.get('type') == 'http' and security.get('scheme') == 'bearer':
                security['type'] = 'apiKey'
                security['name'] = 'Authorization'
                security['in'] = 'header'
                security.pop("scheme", None)
                security.pop("bearerFormat", None)
            elif security.get('type') == 'oauth2' and security.get('flows') is not None:
                flow_name = list(security['flows'].keys())[0]
                flow = security['flows'][flow_name]

                if flow_name == 'clientCredentials':
                    security['flow'] = 'application'
                elif flow_name == 'authorizationCode':
                    security['flow'] = 'accessCode'
                else:
                    security['flow'] = flow_name
                security['authorizationUrl'] = flow.get('authorizationUrl')
                security['tokenUrl'] = flow.get('tokenUrl')
                security['scopes'] = flow.get('scopes')
                security.pop("flows", None)
        spec['components'].pop("securitySchemes", None)

    @classmethod
    def __convert_operation_parameters(cls, operation: dict):
        """
        """
        operation['parameters'] = operation.get('parameters', [])
        if operation.get('requestBody') is not None:
            param = operation.get('requestBody')
            param['name'] = 'body'
            content = param.get('content')
            if isinstance(content, dict) and len(content) > 0:
                media_ranges = list(filter(lambda x: '/' in x, content.keys()))
                media_types = list(filter(lambda x: '*' not in x, media_ranges))
                content_key = None
                if supported_types := cls.__get_supported_mimetypes(content):
                    content_key = supported_types[0]

                del param['content']

                if content_key == SUPPORTED_MIME_TYPES['APPLICATION_X_WWW_URLENCODED'] or content_key == SUPPORTED_MIME_TYPES['MULTIPART_FORM_DATA']:
                    operation['consumes'] = media_types
                    param['in'] = 'formData'
                    param['schema'] = content[content_key].get('schema')

                    if param['schema'].get('type') == 'object' and param['schema'].get('properties') is not None:
                        required = param['schema'].get('required', [])
                        for name in param['schema']['properties']:
                            schema = param['schema']['properties'][name]
                            # readOnly properties should not be sent in requests
                            if not schema.get('readOnly', False):
                                form_data_param = {
                                    'name': name,
                                    'in': 'formData',
                                    'required': name in required,
                                    'schema': schema
                                }
                                operation['parameters'].append(form_data_param)

                    else:
                        operation['parameters'].append(param)

                elif content_key is not None:
                    operation['consumes'] = media_types
                    param['in'] = 'body'
                    param['schema'] = content[content_key].get('schema')
                    operation['parameters'].append(param)
                elif len(media_ranges) > 0:
                    operation['consumes'] = media_types if len(media_types) > 0 else [
                        'application/octet-stream']
                    param['in'] = 'body'
                    param['name'] = param.get('name', 'file')
                    param.pop('type', None)
                    param['schema'] = content[media_ranges[0]].get('schema', {
                        type: 'string',
                        format: 'binary'
                    })
                    operation['parameters'].push(param)

                if param.get('schema') is not None:
                    cls.__convert_schema(param['schema'], 'request')

            operation.pop('requestBody', None)

        cls.__convert_parameters(operation)

    @classmethod
    def __get_supported_mimetypes(cls, content: dict):
        """
        """
        MIME_VALUES = list(SUPPORTED_MIME_TYPES.values())
        return list(
            filter(
                lambda x: x in MIME_VALUES or utils.is_json_mimetype(x),
                content.keys()))
