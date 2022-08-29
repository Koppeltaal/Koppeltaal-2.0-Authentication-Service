#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from flask import Blueprint, redirect

from application.idp_client.service import idp_service


def create_blueprint() -> Blueprint:
    blueprint = Blueprint(__name__.split('.')[-2], __name__)

    @blueprint.route('/idp/oidc/code', methods=['GET'])
    def consume_idp_code():
        url, code = idp_service.consume_idp_code()

        return redirect(url) if code == 302 else url

    return blueprint
