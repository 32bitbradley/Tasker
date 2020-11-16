import yaml
import logging
import json_log_formatter
import waitress
from flask import Flask, jsonify, Blueprint
from blueprints.api_core import bp_api_core
from blueprints.api_tasks import bp_api_tasks

# Load configuration file
with open("config/config.yaml", mode="r") as f:
    config = yaml.safe_load(f.read())

# Init logging
formatter = json_log_formatter.JSONFormatter()
json_handler = logging.FileHandler(filename=config['logging']['location'])
json_handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(json_handler)
if config['logging']['level'] == "DEBUG":
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)
#logger.info('Example log', extra={'Example Key': 'Example Value'})

tasksd = Flask(__name__)

tasksd.register_blueprint(bp_api_core)
tasksd.register_blueprint(bp_api_tasks)


if config == None:
    logger.error("No config file has been loaded.")

if __name__ == "__main__":

    if config['server']['debug'] == True:
        tasksd.run(host=config['server']['host'], port=config['server']['port'], debug=True)
    else:
        waitress.serve(tasksd, host=config['server']['host'], port=config['server']['port'])
