"""
Server module for running this application with Docker
"""
#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

import os

from waitress import serve

from application import create_app

serve(create_app(), host='0.0.0.0', port=os.environ['PORT'] if 'PORT' in os.environ else 8080)
