import os
from flask import Flask

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    new=str(app.instance_path)[:-8]
    app.config.from_mapping(
        SECRET_KEY='187236!&*^#!#^!*736*&!@^#*&@!^#!^@#*^!@638t37534rzrfv16erv7',
        DATABASE=os.path.join(new, "iwaf/waf.db"),
    )

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    # apply the blueprints to the app
    from . import auth, dashboard
    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.add_url_rule("/", endpoint="index")

    return app