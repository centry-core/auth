from queue import Empty
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
        try:
            project_id = self.module.context.rpc_manager.timeout(2).projects_get_personal_project_id(user['id'])
            user['personal_project_id'] = project_id
        except Empty:
            ...
        try:
            auth_ctx = auth.get_referenced_auth_context(g.auth.reference)
            avatar = auth_ctx['provider_attr']['attributes']['picture']
        except (AttributeError, KeyError):
            avatar = None
        user['avatar'] = avatar
        return jsonify(user)
