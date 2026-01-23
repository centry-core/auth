from flask import jsonify
from flask_restful import Resource
from tools import api_tools


class API(Resource):
    def __init__(self, module):
        self.module = module

    url_params = [
        '<string:mode>/<int:project_id>',
    ]

    @api_tools.endpoint_metrics
    def get(self, mode, project_id):
        current_permissions = self.module.resolve_permissions(
            mode=mode,
            project_id=project_id
        )
        return jsonify(list(current_permissions))
