"""
The database definition, the db object is a Singleton database reference, in the app.ethod create_app
this reference gets initialized with the application.
"""
#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from flask_sqlalchemy import SQLAlchemy
#
db: SQLAlchemy = SQLAlchemy()
