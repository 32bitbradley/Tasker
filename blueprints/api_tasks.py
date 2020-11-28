import json
import yaml
import logging
import hashlib
import base64
import os.path
import os
import shutil
import json_log_formatter
from flask import Blueprint, request, jsonify, Flask, render_template, send_file
from datetime import datetime
from .http_helpers import return_response
from .sql_helpers import add_task_type
from .sql_helpers import get_task_type
from .sql_helpers import delete_task_type
from .sql_helpers import add_task
from .sql_helpers import update_task
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
            return return_response(406, "Request is not JSON", False, None, data, 406)

    # Get a task type via GET method
    if request.method == "GET":
        if type_id != None:
            logger.debug('A task type ID has been provided', extra={'type_id':type_id})

            query_results = get_task_type(str(type_id))

            if len(query_results ) > 1:
                logger.error('Dupicate task type ID found in database', extra={'query_results':query_results, 'type_id':type_id})
                return return_response(502, "Duplicate results for that ID", False, None, data, 502)

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
                return return_response(404, "No results found for that ID", False, None, data, 404)
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

                return return_response(404, "No task types found", False, None, data, 404)

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
                        return return_response(406, "The provided bin content is not base64 decodable", False, None, data, 406)
                else:
                    data = {}
                    return return_response(406, "The provided bin does not exist on the manager, and no bin content was provided", False, None, data, 406)

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
                return return_response(502, "Unable to add task type due to an internal error", False, None, data, 502)

        else:
            data = {}
            data['keys'] = request_json.keys()
            return return_response(406, "Request does not contain all the required keys", False, None, data, 406)

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
                    return return_response(406, "You requested to delete all task types, but did not specify confirm.", False, None, data, 406)
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

@bp_api_tasks.route("/type/download/<type_id>", methods=["GET"])
def tasks_type_download_route(type_id=None):
    """This flask def is used to downloads a script for a given task type ID.

    Params:
        id: The task type ID to download, specific as a URL location
    """
    bin_directory = "data/task_bin/"

    if type_id != None:
        logger.debug('A task type ID has been provided to download', extra={'type_id':type_id})

        query_results = get_task_type(str(type_id))

        if len(query_results ) > 1:
            logger.error('Dupicate task type ID found in database', extra={'query_results':query_results, 'type_id':type_id})
            data = []
            return return_response(502, "Duplicate results for that ID", False, None, data, 502)

        elif len(query_results) > 0:
            data = query_results[0]
            return send_from_directory(directory=bin_directory, filename=str(data[4]), as_attachment=True)
        else:
            data = []
            return return_response(404, "No task type found for that ID", False, None, data, 404)
    else:
        return return_response(406, "You did not specify a task type to download", False, None, data, 406)


@bp_api_tasks.route("/task/<url_task_id>", methods=["GET"])
@bp_api_tasks.route("/task", methods=["GET", "PUT", "PATCH", "DELETE"])
def tasks_task_route(url_task_id=None):
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
            return return_response(406, "Request is not JSON", False, None, data, 406)

    # Get a task via GET method
    if request.method == "GET":

        # Pull parameters from request URL query string, set to 'None' if not provided
        if url_task_id != None:
            task_id = url_task_id

            logger.debug('A task ID has been provided in the URL', extra={'task_id':url_task_id})
        elif 'task_id' in request.args:
            task_id = request.args.get('task_id')
            logger.debug('A task_id key has been provided in the query args', extra={'task_id':request.args.get('task_id')})
        else:
            task_id = None

        if 'task_type' in request.args:
            task_type = request.args.get('task_type')
            logger.debug('A target_agent key has been provided in the query args', extra={'task_type':request.args.get('task_type')})
        else:
            task_type = None

        if 'expiration_expired' in request.args:
            expiration_expired = request.args.get('expiration_expired')
            logger.debug('A expiration_expired key has been provided in the query args', extra={'expiration_expired':request.args.get('expiration_expired')})
        else:
            expiration_expired = None

        if 'expiration_datetime' in request.args:
            expiration_datetime = request.args.get('expiration_datetime')
            logger.debug('A expiration_datetime key has been provided in the query args', extra={'expiration_datetime':request.args.get('expiration_datetime')})
        else:
            expiration_datetime = None

        if 'status_status' in request.args:
            status_status = request.args.get('status_status')
            logger.debug('A status_status key has been provided in the query args', extra={'status_status':request.args.get('status_status')})
        else:
            status_status = None

        if 'status_percentage' in request.args:
            status_percentage = request.args.get('status_percentage')
            logger.debug('A status_percentage key has been provided in the query args', extra={'status_percentage':request.args.get('status_percentage')})
        else:
            status_percentage = None

        if 'status_timeout' in request.args:
            status_timeout = request.args.get('status_timeout')
            logger.debug('A status_timeout key has been provided in the query args', extra={'status_timeout':request.args.get('status_timeout')})
        else:
            status_timeout = None

        if 'parameters_json' in request.args:
            parameters_json = request.args.get('parameters_json')
            logger.debug('A parameters_json key has been provided in the query args', extra={'parameters_json':request.args.get('parameters_json')})
        else:
            parameters_json = None

        if 'response_json' in request.args:
            response_json = request.args.get('parameterresponse_jsons_json')
            logger.debug('A response_json key has been provided in the query args', extra={'response_json':request.args.get('response_json')})
        else:
            response_json = None

        if 'target_agent' in request.args:
            target_agent = request.args.get('target_agent')
            logger.debug('A target_agent key has been provided in the query args', extra={'target_agent':request.args.get('target_agent')})
        else:
            target_agent = None
    

        logger.debug('Executing request', extra={'task_id':task_id, 'task_type':task_type,'expiration_expired':expiration_expired, 'expiration_datetime':expiration_datetime, 'status_status':status_status, 'status_percentage':status_percentage, 'status_timeout':status_timeout, 'parameters_json':parameters_json, 'response_json':response_json, 'target_agent':target_agent})

        query_results = get_task(task_id, task_type, expiration_expired, expiration_datetime, status_status, status_percentage, status_timeout, parameters_json, response_json, target_agent)

        if query_results == False:
            data = []
            return return_response(502, "There was an error during the query", False, None, data, 502)
        elif len(query_results) > 0:
            data = query_results
            return return_response(200, "Successfully returned task queery", True, None, data, 200)
        else:
            data = []
            return return_response(404, "No tasks found", False, None, data, 404)

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
                    return return_response(502, "There was an error during the query", False, None, data, 502)
                elif len(query_results) > 0:
                    data = query_results
                    return return_response(201, "Added task successfully", True, None, data, 201)
                else:
                    data =[]
                    logger.error("No tasks returned from DB for a ID that was just added", extra={'task_id':task_id, 'query_results':query_results})
                    return return_response(404, "Unable to add task due to an internal error", False, None, data, 404)
            else:
                data = task_request
                return return_response(502, "Unable to add task due to an internal error", False, None, data, 502)

        else:
            data = {}
            data['keys'] = []
            for key in request_json.keys():
                data['keys'].append(key)

            return return_response(406, "Request does not contain all the required keys", False, None, data, 406)

    # Adding a new task via PUT method
    elif request.method == "PATCH":

        # Checking required keys (All must be provided for a PATCH, as the sender should have all the data anyway from a previous GET)
        if ("task" in request_json) and \
            ("id" in request_json['task']) and \
            ("type" in request_json['task']) and \
            ("target" in request_json) and \
            ("agent" in request_json['target']) and \
            ("status" in request_json) and \
            ("status" in request_json['status']) and \
            ("percentage" in request_json['status']) and \
            ("timeout" in request_json['status']) and \
            ("expiration" in request_json) and \
            ("expired" in request_json['expiration']) and \
            ("timestamp" in request_json['expiration']) and \
            ("parameters" in request_json):

            logger.debug('Updating task', extra={'request_json':request_json})
            
            # Copy request_json to task_request so we can properly set the timestamp to a pythonic timestamp
            task_request = request_json
            task_request['expiration']['timestamp'] = datetime.fromtimestamp(request_json['expiration']['timestamp'])

            task_id = update_task(task_request)
            logger.debug("Updated task in the DB", extra={'task_id':task_id})

            if task_id != None:

                query_results = get_task(str(task_request['task']['id']))

                if query_results == False:
                    data = []
                    return return_response(502, "There was an error during the query", False, None, data, 502)
                elif len(query_results) > 0:
                    data = query_results
                    return return_response(201, "Updated task successfully", True, None, data, 201)
                else:
                    data =[]
                    logger.error("No tasks returned from DB for a ID that was just added", extra={'task_id':task_id, 'query_results':query_results})
                    return return_response(404, "Unable to update task due to an internal error", False, None, data, 404)
            else:
                data = task_request
                return return_response(502, "Unable to update task due to an internal error", False, None, data, 502)

        else:
            data = {}
            data['keys'] = []
            for key in request_json.keys():
                data['keys'].append(key)

            return return_response(406, "Request does not contain all the required keys", False, None, data, 406)

    # Delete task types
    elif request.method == "DELETE":

        if ("id" in request_json):

            if request_json['id'] == "all":
                if ("confirm" in request_json) and (request_json['confirm'] == True):

                    query_results = get_task(None)

                    if query_results == False:
                        data = []
                        return return_response(502, "There was an error during the query", False, None, data, 502)
                    elif len(query_results) == 0:
                        data = []
                        logger.debug("No tasks to delete", extra={'task_id':request_json['id'], 'query_results':query_results})
                        return return_response(200, "No tasks to delete", True, None, data, 200)
                    else:
                        
                        delete_task(None)
                    
                    data = query_results
                    return return_response(200, "All tasks deleted successfully", True, None, data, 200)

                else:
                    return return_response(406, "You requested to delete all tasks, but did not specify confirm.", False, None, data, 406)
            else:

                query_results = get_task(str(request_json['id']))

                if query_results == False:
                    data = []
                    return return_response(502, "There was an error during the query", False, None, data, 502)
                elif len(query_results) == 0:
                    data = []
                    logger.error("No task found for that ID", extra={'task_id':request_json['id'], 'query_results':query_results})
                    return return_response(404, "No task found for that ID", True, None, data, 404)
                else:
                    
                    for result in query_results:
                        delete_task(result['task']['id'])
                        
                    data = query_results
                    return return_response(200, "Task deleted successfully", True, None, data, 200)