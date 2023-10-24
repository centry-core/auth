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
        return jsonify(user)
