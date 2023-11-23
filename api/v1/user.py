from flask import g, request, jsonify
from pylon.core.tools import log

from tools import api_tools, auth, config as c


class API(api_tools.APIBase):
    url_params = [
        '<string:mode>',
        '',
    ]

    # mode_handlers = {
    #     c.DEFAULT_MODE: ProjectAPI,
    # }

    def get(self, **kwargs):
        user = self.module.current_user()
        project_id = self.module.context.rpc_manager.timeout(2).projects_get_personal_project_id(user['id'])
        user['personal_project_id'] = project_id
        return jsonify(user)
