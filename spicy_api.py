import hashlib
import json
import random
import string
import sys

from flask import Flask, request

from firebase_interface import FirebaseInterface
from queuingutils.publisher import Publisher
import logging
import datetime

spicy_api = Flask(__name__)

with open("creds.json") as file:
    creds = json.load(file)

FIREBASE_OBJ = FirebaseInterface(creds_dict=creds)
PROJECT_ID = 'pub-sub132608'
TOPIC_NAME = 'api-pub'
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
recorded_time = datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S.%f)")
logging.info('Program starting\n')
logging.info(f"{recorded_time}\n")

"""
################### Helper Functions #########################
"""


def encode(raw_string):
    """

    This function replaces all periods with "_DOT_" in order to be
    input into the Firebase database.

    :param raw_string: String containing the user's email
    :return: str:encoded user email
    """
    encoded_string = raw_string.replace(".", "_DOT_")
    return encoded_string


def decode(encoded_string):
    """

    This function replaces all of the instances of "_DOT_" with a
    period, undoing the encoding from encode()

    :param encoded_string: str:encoded user email
    :return: str:original user email
    """
    decoded_string = encoded_string.replace("_DOT_", ".")
    return decoded_string


def turn_off_vehicle(vehicle_id):
    """

    This function will "turn off" the car with the specified vehicle
    id.

    What is turned off when the vehicle is turned off?

    - carOn
    - defrost['front']
    - defrost['back]
    - seatHeater[bDriver]
    - seatHeater[bPass]
    - seatHeater[fDriver]
    - seatHeater[fPass]

    :param vehicle_id: str:unique identifier for a vehicle
    :return:
    """
    # retrieve the data corresponding to the desired vehicle
    vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                         subkey=vehicle_id)

    # isolate the vehicle's states
    current_states = vehicle_data['states']

    # Turn the car off
    current_states['carOn'] = False

    # Turn all defrosting off
    new_defrost = current_states['defrost']

    for key in new_defrost.keys():
        new_defrost[key] = False

    # Turn all seat heaters off
    new_seat_heater = current_states['seatHeater']

    for key in new_seat_heater.keys():
        new_seat_heater[key] = False

    # add the updated values to the states dictionary
    current_states['defrost'] = new_defrost
    current_states['seatHeater'] = new_seat_heater

    # pass the updated dictionary to the firebase database
    set_response = FIREBASE_OBJ.change_value(key=f'vehicles/{vehicle_id}',
                                             subkey='states',
                                             val=current_states)

    return set_response


def build_subscriber_name(sender):
    """

    This function takes the sender type which could be either app or
    vehicle and returns the appropriate name of the subscriber to send
    the message to.

    :param sender:
    :return:
    """
    if sender == "app":
        return f"sub_vehicle"
    elif sender == "vehicle":
        return f"sub_app"
    return False


# Generates a token
def gen_token():
    """

    This function generates a token with random characters and a random length
    then returns it.

    :return: str:token
    """
    logging.info('Generating Token\n')
    # Define all possible characters the token can contain as a set of alphanumeric characters
    possible_chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    # Start with an empty string and add a random character to that 25-35 times
    # noinspection PyUnusedLocal
    return ''.join(random.choice(possible_chars) for i in range(random.randint(25, 35)))


def hash_string_with_salt(input_string, salt):
    """

    This function takes in a value to be hashed and salted and a custom
    salt. It will then hash and salt the input_string and return it as
    a string.

    :param input_string: str:value to be hashed and salted
    :param salt: str:value used to salt input_string
    :return: str:hashed and salted input_string
    """
    if isinstance(input_string, str):
        input_string = input_string.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    return str(hashlib.pbkdf2_hmac('sha512', input_string, salt, 100000)).replace("/", "")


def get_user(token):
    """

    This function retrieves user info by passing in that user's token.

    :param token: str:users unique token for access
    :return: dict:user data
    """
    logging.info("Getting user.\n")
    if token is None:
        return None

    users = FIREBASE_OBJ.get_data(key=f'users')

    if users is None:
        logging.error("get_user: Error in retrieving users.\n")
        raise ValueError("get_user: Error in retrieving users.")

    for user in users.keys():
        hashed_token = hash_string_with_salt(token, users[user]['salt'])
        # Look through all users for the user holding the passed in token
        try:
            if users[user]['token'] == hashed_token:
                logging.info("Returning user info.\n")
                return users[user]
        except KeyError:
            # The user doesn't have a token
            continue

    logging.warning("User could not be found or verified.\n")
    return None


def can_access_vehicle(user, vehicle_id):
    """

    This function verifies whether or not a user can access a vehicle
    by user data and vehicle id.

    :param user: dict:user data from the database
    :param vehicle_id: str:unique identifier for the vehicle
    :return: True if the user can access and False if they can't
    """
    if user is None:
        logging.error("can_access_vehicle: user is NoneType\n")
        raise ValueError('can_access_vehicle: user is NoneType\n')

    logging.info("Verifying user access.\n")
    for item in user['vehicle']:
        # For users that only have 1 vehicle
        if isinstance(user['vehicle'], str):
            if user['vehicle'] == vehicle_id:
                return True
        # For users that have multiple vehicles
        elif isinstance(user['vehicle'], dict):
            if user['vehicle'][item] == vehicle_id:
                return True
    return False


"""
################### Flask Routes #########################
"""


@spicy_api.route("/", methods=['GET'])
def index():
    """

    This route will display all routes available on the Spicy API as
    well as a link to it's documentation

    :return: str:html render of the API's routes
    """
    html_render = '<h1>Spicy API</h1>' \
                  '<h3>Routes</h3>' \
                  '<ul>' \
                  '<li>revoke_token</li>' \
                  '<li>verify_token</li>' \
                  '<li>attempt_login</li>' \
                  '<li>get_vehicle_ids</li>' \
                  '<li>get_vehicle_data</li>' \
                  '<li>set_val</li>' \
                  '</ul>' \
                  '<p>Docs ' \
                  '<a href="https://documenter.getpostman.com/view/7634315/SzS7Rmsp?version=latest">' \
                  'here</a></p>'
    return html_render


# Temporary, we shouldn't keep this long term
@spicy_api.route("/get_full_database", methods=['GET'])
def get_full_database():
    """

    This route retrieves all contents of the database.

    :return: string-json:database contents
    """
    logging.info("Retrieving whole database from Firebase\n")
    return FIREBASE_OBJ.get_data()


# Revoke a token (Should be done on logout)
@spicy_api.route("/revoke_token", methods=['POST'])
def revoke_token():
    """

    This function doesn't really do anything right now

    post_request sample: {
        "token": "token",
    }

    :return: string-json:success status
    """
    post_request = request.json
    logging.info("Revoking token.\n")
    try:
        token = post_request['token']
    except KeyError:
        logging.error("Missing login token.\n")
        raise KeyError("Missing login token.")
    # user = get_user(token)
    return "{\"success\": false}"


# Verify that your token is still valid
@spicy_api.route("/verify_token", methods=['POST'])
def verify_token():
    """

    This route receives a token and verifies it in the database.

    post_request sample: {
        "token": "token",
    }

    :return: string-json:success status
    """
    post_request = request.json
    logging.info("Verifying Token\n")
    try:
        token = post_request['token']
    except KeyError:
        logging.error("Missing login token.\n")
        raise KeyError("VerifyToken: Missing login token.")
    user = get_user(token)
    if user is None:
        raise ValueError("VerifyToken: Invalid login token.")
    return "{\"success\": true}"


# Attempt to log in to the server, returns the error message if it fails or the provided credentials are invalid
@spicy_api.route("/attempt_login", methods=['POST'])
def attempt_login():
    """

    This route receives a username and password and checks the database
    to make sure they correspond to the credentials held in the database.
    If they do, it will return a token to the client.

    post_request sample: {
        "username": "username",
        "password": "password",
    }

    :return: string-json:token
    """
    post_request = request.json

    logging.info("Attempting Login\n")

    try:
        username = post_request['username']
        password = post_request['password']
    except KeyError:
        logging.error("Missing username or password.\n")
        raise KeyError("Missing username or password.")

    if password is None or username is None:
        logging.error("Missing username or password.\n")
        raise ValueError("Missing username or password.")

    logging.info("Getting user data\n")
    user = FIREBASE_OBJ.get_data(key=f'users',
                                 subkey=encode(username))

    if user is None:
        logging.error("Invalid username or password.\n")
        raise ValueError("Invalid username or password.")

    logging.info("Verifying Password\n")

    if hash_string_with_salt(password, user['salt']) == user['password']:
        token = gen_token()
        hashed_token = hash_string_with_salt(token, user['salt'])
        # Attempt to store hashed_token in the database as one of the user's tokens. This should be tested.
        FIREBASE_OBJ.add_value(key=f'users/{encode(username)}', subkey='token', val=hashed_token)
        logging.info("Issuing token.\n")
        return {"token": f"{token}"}
    else:
        logging.warning("Invalid username or password.\n")
        raise ValueError("Invalid username or password.")


@spicy_api.route("/get_vehicle_id", methods=['POST'])
def get_vehicle_ids():
    """

    This route retrieves all of a user's vehicle ID's from the database

    post_request sample: {
        "token": "token",
    }

    :return:
    """
    post_request = request.json
    logging.info("Getting vehicle IDs.\n")
    try:
        token = post_request['token']
    except KeyError:
        logging.error("Missing login token\n")
        raise KeyError("Missing login token.")
    user = get_user(token)
    logging.info("Returning vehicle IDs.\n")
    return user['vehicle']


@spicy_api.route("/get_vehicle_data", methods=['POST'])
def get_vehicle_data():
    """

    This route retrieves a vehicle's data from the database

    post_request sample: {
        "token": "token",
        "vehicle_id": "vehicle1",
    }

    :return: json containing the vehicle's data
    """
    post_request = request.json
    try:
        token = post_request['token']
    except KeyError:
        logging.error("Missing login token.\n")
        raise KeyError("Missing login token.")

    user = get_user(token)

    try:
        vehicle_id = post_request['vehicle_id']
    except KeyError:
        logging.error('No vehicle id provided.\n')
        raise KeyError("No vehicle id provided.")

    if vehicle_id is None or vehicle_id == "":
        logging.error('No vehicle id provided.\n')
        raise KeyError("No vehicle id provided.")

    if can_access_vehicle(user, vehicle_id):
        logging.info("Getting vehicle data from Firebase\n")

        vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                             subkey=vehicle_id)

        if vehicle_data is None:
            logging.warning(f"No vehicle data found for {vehicle_data}.")
            raise ValueError(f"No vehicle data found for {vehicle_data}.")

        return vehicle_data
    else:
        logging.warning("You are not authorized to view this vehicle's data")
        raise PermissionError("You are not authorized to view this vehicle's data")


@spicy_api.route("/set_val", methods=['POST'])
def set_val():
    """

    This route changes a value in the database

    Example POST Request
    post_request = {
        "vehicle_id": "string",
        "key": "string",
        "subkey": "string",  # Optional
        "new_val": bool,
        "sender": "string" # app or device
    }
    :return: bool indicating whether or not the update was successful
    """
    post_request = request.json

    logging.info("Changing state for a vehicle.\n")

    vehicle_id = post_request['vehicle_id']
    key = post_request['key']
    new_val = post_request['new_val']
    sender = post_request['sender']

    try:
        subkey = post_request['subkey']
    except KeyError:
        subkey = None

    publisher = Publisher(PROJECT_ID, TOPIC_NAME)
    # build the subscriber name
    sub_name = build_subscriber_name(sender)
    # check if the request is to turn off the car
    if key == 'carOn' and new_val is False:
        logging.info('Turning car off\n')

        set_response = turn_off_vehicle(vehicle_id)

        if set_response is None:
            logging.error("Unable to set vehicle states to False.\n")
            raise NotImplementedError("Unable to set vehicle states to False.")
        else:
            logging.info("Retrieving updated vehicle information from Firebase\n")
            vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                                 subkey=vehicle_id)

            logging.info(f"Sending message to {sub_name}\n")

            # Assumes that the subscribers already exist
            publisher.publish_message(vehicle_data['states'], recipient=sub_name)

            return {"success": True, "message": f"Sending message to {sub_name}"}

    logging.info("Updating Firebase\n")

    response = FIREBASE_OBJ.change_value(key=f"vehicles/{vehicle_id}/states/{key}",
                                         subkey=subkey,
                                         val=new_val)

    logging.info("Retrieving updated vehicle information from Firebase\n")

    vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                         subkey=vehicle_id)

    if response is None:
        logging.error('Unable to change state of vehicle.\n')
        raise NotImplementedError('Unable to change state of vehicle.')
    else:
        publisher.publish_message(vehicle_data['states'], recipient=sub_name)

        logging.info(f"Alerting {sub_name} of {sender}\'s changes")

        return {"success": True, "message": f"Sending message to {sub_name}"}


if __name__ == "__main__":
    spicy_api.run(debug=True, host='0.0.0.0', port="8080")
