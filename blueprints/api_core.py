import json
import yaml
import logging
import json_log_formatter
from flask import Blueprint, jsonify, Flask, render_template
from .http_helpers import return_response

# Load configuration file
with open("config/config.yaml", mode="r") as f:
    config = yaml.safe_load(f.read())

# Init logging
logger = logging.getLogger()
if config['logging']['level'] == "DEBUG":
    logger.setLevel(logging.INFO)
else:
    logger.setLevel(logging.INFO)
#logger.info('Example log', extra={'Example Key': 'Example Value'})

bp_api_core = Blueprint("core", __name__, url_prefix="/api")

@bp_api_core.route("/ping", methods=["GET"])
def pong():
    data = {}
    data['ping'] = "Pong!"
    return return_response(0, "Pong!", True, None, data, 200)