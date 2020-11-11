from flask import jsonify

def return_response(error, message, success, meta, data, http_code):
    """Will return a JSON response to the request.

    Params: 
    exception_code: The internal, execption code to return
    exception_message: The message to return
    success: True or False, depending of the message was a success. True being success.
    meta_items: A count of the lenght of the amount of items in the data object
    data: An array of objects to return as the data field
    http_code: The HTTP error code to return

    Response:
    A JSON response
    A HTTP error code
    """
    if not data:
        data = {}

    if meta == None:
        meta = {}
    
    meta['items'] = len(data)

    return jsonify({
        "error": error,
        "message": message,
        "success": success,
        "meta": meta,
        "data": data
        }), http_code

