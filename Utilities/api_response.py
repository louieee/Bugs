from collections import OrderedDict

from rest_framework.renderers import JSONRenderer


class CustomJSONRenderer(JSONRenderer):
    '''Override the default JSON renderer to be consistent and have additional keys'''

    def render(self, data, accepted_media_type=None, renderer_context=None):
        status_code = renderer_context['response'].status_code
        status = True if status_code < 400 else False
        message = 'successful' if status else 'failed'

        # when response data is a list, convert to dict
        if isinstance(data, list):
            data = {
                'status': status,
                'message': message,
                'data': data
            }

        # if response data is none, convert to dict
        if data is None:
            data = {}

        # if response data is not well formated dict, and not an error response, convert to right format
        if isinstance(data, OrderedDict) and ('data' not in data) and ('non_field_errors' not in data):
            data = {
                'status': status,
                'message': message,
                'data': data,
            }

        # convert non_field_errors message to text, instead of list
        if 'non_field_errors' in data:
            data['message'] = data.pop('non_field_errors')[0]

        # if not `status` in response, add status
        if not 'status' in data:
            data['status'] = status

        # if no `message` in response, add message based on status
        if not 'message' in data:
            data['message'] = message

        return super().render(data, accepted_media_type, renderer_context)
