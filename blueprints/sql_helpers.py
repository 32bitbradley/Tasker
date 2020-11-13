import random
import string
import logging
import json_log_formatter
from sqlalchemy import engine, create_engine, MetaData, Table, Column, Integer, Text, String, Float, select, TIMESTAMP
import json
import yaml

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

engine_url = config['database']['type'] + "://" + config['database']['username'] + ":" + config['database']['password'] + "@" + config['database']['host'] + "/" + config['database']['database']
engine.url.make_url(engine_url)
engine = create_engine(engine.url.make_url(engine_url))

metadata = MetaData()
db_tasks_types = Table('types', metadata,
    Column('id', String(16), primary_key=True),
    Column('name', String(255)),
    Column('target', String(255)),
    Column('version', Float(12)),
    Column('bin', String(255)),
    Column('shasum', String(255)),
    Column('track_progress', String(255)),
)
db_tasks = Table('tasks', metadata,
    Column('id', String(16), primary_key=True),
    Column('task_type', String(255)),
    Column('target_agent', String(255)),
    Column('expiration_expired', String(255)),
    Column('expiration_datetime', TIMESTAMP),
    Column('status_status', String(255)),
    Column('status_percentage', Integer),
    Column('status_timeout', String(255)),
    Column('parameters_json', Text),
    Column('response_json', Text),
)
def id_generator(size=16, chars=string.ascii_uppercase + string.digits):
    """Will generate and return a random 16 character ID

    Params:
    size: The length of the string to generate
    chars: The type of characters to include in the random string

    Returns:
    A random string
    """
    return str(''.join(random.choice(chars) for x in range(size)))

def add_task_type(type_info):

    type_id = id_generator()

    statement = db_tasks_types.insert().values(
        id=str(type_id),
        name=str(type_info['name']),
        target=str(type_info['target']),
        version=float(type_info['version']),
        bin=str(type_info['bin']['name']),
        shasum=str(type_info['shasum']),
        track_progress=str(type_info['track_progress'])
        )

    logger.debug('Executing SQL', extra={'statement': statement})
    with engine.begin() as conn:
        conn.execute(statement)

    return type_id

def get_task_type(type_id):

    if type_id  != None:
        statement = db_tasks_types.select().where(
            db_tasks_types.c.id == str(type_id)
            )
    else:
        statement = db_tasks_types.select()

    query_results = None

    logger.debug('Executing SQL', extra={'statement': statement})
    with engine.begin() as conn:
        query_results = conn.execute(statement).fetchall()

    return query_results

def delete_task_type(type_id):

    if type_id  != None:
        statement = db_tasks_types.delete().where(
            db_tasks_types.c.id == str(type_id)
            )
    else:
        statement = db_tasks_types.delete()

    logger.debug('Executing SQL', extra={'statement': statement})
    with engine.begin() as conn:
        conn.execute(statement)

    return True

def add_task(task_info):

    task_id = id_generator()

    statement = db_tasks.insert().values(
        id=str(task_id),
        task_type=str(task_info['task']['type']),
        target_agent=str(task_info['target']['agent']),
        expiration_expired=str("False"),
        expiration_datetime=task_info['expiration']['timestamp'],
        status_status=str("pending"),
        status_percentage=int(0),
        status_timeout=str("False"),
        parameters_json=str(task_info['parameters']),
        response_json=None,
        )

    logger.debug('Executing SQL', extra={'statement': statement})
    with engine.begin() as conn:
        conn.execute(statement)

    return task_id

def get_task(type_id):

    if type_id  != None:
        statement = db_tasks.select().where(
            db_tasks.c.id == str(type_id)
            )
    else:
        statement = db_tasks.select()

    query_results = None

    logger.debug('Executing SQL', extra={'statement': statement})
    with engine.begin() as conn:
        query_results = conn.execute(statement).fetchall()

    return query_results

def delete_task(type_id):

    if type_id  != None:
        statement = db_tasks.delete().where(
            db_tasks.c.id == str(type_id)
            )
    else:
        statement = db_tasks.delete()

    logger.debug('Executing SQL', extra={'statement': statement})
    with engine.begin() as conn:
        conn.execute(statement)

    return True