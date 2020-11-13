import json
import yaml
import logging
import hashlib
import base64
import os.path
import os
import shutil
import json_log_formatter
from flask import Blueprint, request, jsonify, Flask, render_template
from datetime import datetime
from .http_helpers import return_response
from .sql_helpers import add_task_type
from .sql_helpers import get_task_type
from .sql_helpers import delete_task_type
from .sql_helpers import add_task
from .sql_helpers import get_task
from .sql_helpers import delete_task

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

def is_base64(sb):
    """Will check if a provided string or bytes is base64 decodable, and trurn true or false
    Params:
        sb: The variable to check
    """
    try:
            if isinstance(sb, str):
                    # If there's any unicode here, an exception will be thrown and the function will return false
                    sb_bytes = bytes(sb, 'ascii')
            elif isinstance(sb, bytes):
                    sb_bytes = sb
            else:
                    raise ValueError("Argument must be string or bytes")
            if base64.b64encode(base64.b64decode(sb_bytes)):
                return True
    except Exception:
            return False

bp_api_tasks = Blueprint("tasks", __name__, url_prefix="/api/tasks")

@bp_api_tasks.route("/type/<type_id>", methods=["GET"])
@bp_api_tasks.route("/type", methods=["GET", "PUT", "DELETE"])
def tasks_type_route(type_id=None):
    """This flask def is used to manage task types. Including getting info on a task type, adding a new task type and deleting a task type.

    Params:
        A JSON request body handled by flask which may include:
            name: The name of the task type (String)
            target: The type of target for this task type, ie agent. (String)
            version: The version number for this task type (Float)
            bin.name: The name of the bin for this task type (String)
            bin.content: The base64 encoded content of the task type script (String)
            track_progress: Should this task type track progress (Boolean)

    Returns:
        A JSON formatting string of task type related information.
    """
    # Check the request is json.
    if request.method != "GET":
        if request.is_json:
            request_json = request.get_json()
        else:
            data = {}
            return return_response(406, "Request is not JSON", True, None, data, 406)

    # Get a task type via GET method
    if request.method == "GET":
        if type_id != None:
            logger.debug('A task type ID has been provided', extra={'type_id':type_id})

            query_results = get_task_type(str(type_id))

            if len(query_results ) > 1:
                logger.error('Dupicate task type ID found in database', extra={'query_results':query_results, 'type_id':type_id})
                return return_response(502, "Duplicate results for that ID", True, None, data, 502)

            elif len(query_results) > 0:

                data = []

                for row in query_results:
                    tmp_data = {}   
                    tmp_data["id"] = row[0]
                    tmp_data["name"] = row[1]
                    tmp_data["target"] = row[2]
                    tmp_data["version"] = row[3]
                    tmp_data["bin"] = row[4]
                    tmp_data["shasum"] = row[5]
                    tmp_data["track_progress"] = row[6]
                    data.append(tmp_data)
                
                return return_response(200, "Successfully returned task type", True, None, data, 200)
            
            else:

                data = {}
                return return_response(404, "No results found for that ID", True, None, data, 404)
        
        else:

            logger.debug('No task type ID has been provided, getting all task types', extra={'type_id':type_id})

            query_results = get_task_type(None)

            if len(query_results) > 0:

                data = []

                for row in query_results:
                    tmp_data = {}   
                    tmp_data["id"] = row[0]
                    tmp_data["name"] = row[1]
                    tmp_data["target"] = row[2]
                    tmp_data["version"] = row[3]
                    tmp_data["bin"] = row[4]
                    tmp_data["shasum"] = row[5]
                    tmp_data["track_progress"] = row[6]
                    data.append(tmp_data)
                
                return return_response(200, "Successfully returned all task types", True, None, data, 200)

            else:

                data = {}

                return return_response(404, "No task types found", True, None, data, 404)

    # Adding a new task via PUT method
    elif request.method == "PUT":

        if ("name" in request_json) and ("target" in request_json) and ("version" in request_json) and ("bin" in request_json) and ("track_progress" in request_json) and ("name" in request_json['bin']):

            task_type = request_json

            # Checking that the provide bin file name exists on the system
            if os.path.isfile(f"data/task_bin/{task_type['bin']['name']}"):
                logger.debug('Provioded bin file does exist on the system', extra={'bin':task_type['bin']['name']})
            else:
                logger.debug('Provioded bin file does not exist on the system', extra={'bin':task_type['bin']['name']})

                # If the file does not exist, but we have been provided the content bas base64, write it.
                if "content" in request_json['bin']:
                    logger.debug('Content has been provoided, decoding and writing to file', extra={'bin':task_type['bin']['name']})

                    if is_base64(task_type['bin']['content']):

                        with open(f"data/task_bin/{task_type['bin']['name']}", "wb") as target_file:
                            target_file.write(base64.decodebytes(bytes(task_type['bin']['content'], 'ascii')))

                        logger.debug('Written file', extra={'bin':task_type['bin']['name']})
                    else:
                        logger.debug('Provide content is not base64 decodable', extra={'bin':task_type['bin']['name']})
                        data = {}
                        return return_response(406, "The provided bin content is not base64 decodable", True, None, data, 406)
                else:
                    data = {}
                    return return_response(406, "The provided bin does not exist on the manager, and no bin content was provided", True, None, data, 406)

            # Generate SHA256 sum for the bin file
            logger.debug('Generating SHA256 hash for bin', extra={'bin':task_type['bin']['name']})

            sha256_hash = hashlib.sha256()
            with open(f"data/task_bin/{task_type['bin']['name']}","rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)
                logger.debug('Generated SHA256 hash', extra={'hash':sha256_hash.hexdigest()})
                task_type['shasum'] = str(sha256_hash.hexdigest())
            
            logger.debug('Adding new task type', extra={'task_type':task_type})

            task_id = add_task_type(task_type)

            if task_id != None:
                data = task_type
                data['id'] = task_id
                return return_response(201, "Added request type successfully", True, None, data, 201)
            else:
                data = task_type
                return return_response(502, "Unable to add task type due to an internal error", True, None, data, 502)

        else:
            data = {}
            data['keys'] = request_json.keys()
            return return_response(406, "Request does not contain all the required keys", True, None, data, 406)

    # Delete task types
    elif request.method == "DELETE":

        if ("id" in request_json):

            type_id = request_json['id']

            if type_id == "all":
                if ("confirm" in request_json) and (request_json['confirm'] == True):

                    # Delete all bin files
                    bin_folder = 'data/task_bin'
                    for filename in os.listdir(bin_folder):
                        file_path = os.path.join(bin_folder, filename)
                        try:
                            if os.path.isfile(file_path) or os.path.islink(file_path):
                                os.unlink(file_path)
                            elif os.path.isdir(file_path):
                                shutil.rmtree(file_path)
                        except Exception as e:
                            logger.error('Failed to delete %s. Reason: %s' % (file_path, e))

                    
                    delete_task_type(None)
                    data = []
                    data.append(str(type_id))

                    return return_response(200, "All task types deleted successfully", True, None, data, 200)

                else:
                    return return_response(406, "You requested to delete all task types, but did not specify confirm.", True, None, data, 406)
            else:

                query_results = get_task_type(str(type_id))

                if len(query_results ) > 1:
                    logger.error('Dupicate task type ID found in database, deleting all results', extra={'query_results':query_results, 'type_id':type_id})

                elif len(query_results) > 0:

                    data = []

                    # For every task type in the databse with that ID, delete the file and delete from the db
                    for row in query_results:
                        tmp_data = {}   
                        tmp_data["id"] = row[0]
                        tmp_data["name"] = row[1]
                        tmp_data["target"] = row[2]
                        tmp_data["version"] = row[3]
                        tmp_data["bin"] = row[4]
                        tmp_data["shasum"] = row[5]
                        tmp_data["track_progress"] = row[6]
                        data.append(tmp_data)

                        file_name = f"data/task_bin/{tmp_data['bin']}"
                        if os.path.exists(file_name):
                            os.remove(file_name)
                        else:
                            logger.error('Could not find bin when deleting task type, continuing anyway', extra={'bin':data[0]['bin'], 'file_name':file_name})
                    
                        delete_task_type(type_id)
                        
                    return return_response(200, "Task type deleted successfully", True, None, data, 200)

@bp_api_tasks.route("/type/download/<id>", methods=["GET"])
def tasks_type_download_route():
    """This flask def is used to downloads a script for a given task type ID.

    Params:
        id: The task type ID to download, specific as a URL location
    """
    data = {}
    data['ping'] = "Pong!"
    return return_response(0, "Pong!", True, None, data, 200)










@bp_api_tasks.route("/task/<task_id>", methods=["GET"])
@bp_api_tasks.route("/task", methods=["GET", "PUT", "DELETE"])
def tasks_task_route(task_id=None):
    """This flask def is used to manage tasks. Including getting info on a task , adding a new task  and deleting a task.

    Params:
        A JSON request body handled by flask which may include:
            task.type: The type of task to create, must by a vaid task type.
            target.agent: The agent name to run this task on
            expiration.datet this task to expire, provided as a UTC timestamp as an integer
            parameters: A dictionary of paramaters to pass to the task.

    Returns:
        A JSON formatting string of task related information.
    """
    # Check the request is json.
    if request.method != "GET":
        if request.is_json:
            request_json = request.get_json()
        else:
            data = {}
            return return_response(406, "Request is not JSON", True, None, data, 406)

    # Get a task via GET method
    if request.method == "GET":
        if task_id != None:
            logger.debug('A task ID has been provided', extra={'task_id':task_id})

            query_results = get_task(str(task_id))

            if query_results == False:
                data = []
                return return_response(502, "There was an error during the query", True, None, data, 502)
            elif len(query_results) > 0:
                data = query_results
                return return_response(200, "Successfully returned task", True, None, data, 200)
            else:
                data =[]
                return return_response(404, "No results found for that ID", True, None, data, 404)
        
        else:

            logger.debug('No task ID has been provided, getting all tasks', extra={'task_id':task_id})

            query_results = get_task(None)

            if query_results == False:
                data = []
                return return_response(502, "There was an error during the query", True, None, data, 502)
            elif len(query_results) > 0:
                data = query_results
                return return_response(200, "Successfully returned all tasks", True, None, data, 200)
            else:
                data =[]
                return return_response(404, "No tasks found", True, None, data, 404)

    # Adding a new task via PUT method
    elif request.method == "PUT":

        if ("task" in request_json) and ("target" in request_json) and ("parameters" in request_json) and ("type" in request_json['task']) and ("agent" in request_json['target']) and ("timestamp" in request_json['expiration']):

            logger.debug('Adding new task', extra={'request_json':request_json})
            
            # Copy request_json to task_request so we can properly set the timestamp to a pythonic timestamp
            task_request = request_json
            task_request['expiration']['timestamp'] = datetime.fromtimestamp(request_json['expiration']['timestamp'])

            task_id = add_task(task_request)
            logger.debug("Added a new task to the DB", extra={'task_id':task_id})

            if task_id != None:

                query_results = get_task(str(task_id))

                if query_results == False:
                    data = []
                    return return_response(502, "There was an error during the query", True, None, data, 502)
                elif len(query_results) > 0:
                    data = query_results
                    return return_response(201, "Added task successfully", True, None, data, 201)
                else:
                    data =[]
                    logger.error("No tasks returned from DB for a ID that was just added", extra={'task_id':task_id, 'query_results':query_results})
                    return return_response(404, "Unable to add task due to an internal error", True, None, data, 404)
            else:
                data = task_request
                return return_response(502, "Unable to add task due to an internal error", True, None, data, 502)

        else:
            data = {}
            data['keys'] = []
            for key in request_json.keys():
                data['keys'].append(key)

            return return_response(406, "Request does not contain all the required keys", True, None, data, 406)

    # Delete task types
    elif request.method == "DELETE":

        if ("id" in request_json):

            if request_json['id'] == "all":
                if ("confirm" in request_json) and (request_json['confirm'] == True):

                    query_results = get_task(None)

                    if query_results == False:
                        data = []
                        return return_response(502, "There was an error during the query", True, None, data, 502)
                    elif len(query_results) == 0:
                        data = []
                        logger.debug("No tasks to delete", extra={'task_id':request_json['id'], 'query_results':query_results})
                        return return_response(200, "No tasks to delete", True, None, data, 200)
                    else:
                        
                        delete_task(None)
                    
                    data = query_results
                    return return_response(200, "All tasks deleted successfully", True, None, data, 200)

                else:
                    return return_response(406, "You requested to delete all tasks, but did not specify confirm.", True, None, data, 406)
            else:

                query_results = get_task(str(request_json['id']))

                if query_results == False:
                    data = []
                    return return_response(502, "There was an error during the query", True, None, data, 502)
                elif len(query_results) == 0:
                    data = []
                    logger.error("No task found for that ID", extra={'task_id':request_json['id'], 'query_results':query_results})
                    return return_response(404, "No task found for that ID", True, None, data, 404)
                else:
                    
                    for result in query_results:
                        delete_task(result['task']['id'])
                        
                    data = query_results
                    return return_response(200, "Task deleted successfully", True, None, data, 200)