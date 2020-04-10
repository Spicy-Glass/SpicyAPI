import hashlib
import json
import random
import string

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
logging.basicConfig(filename='program.log', level='INFO')
recorded_time = datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S.%f)")
logging.info('Program starting\n')
logging.info(recorded_time)

def encode(raw_string):
    encoded_string = raw_string.replace(".", "_DOT_")
    return encoded_string


def decode(encoded_string):
    raw_string = encoded_string.replace("_DOT_", ".")
    return raw_string


def turn_off_vehicle(vehicle_id):
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

    logging.info('Setting all of the vehicles states to false')

    # pass the updated dictionary to the firebase database
    set_response = FIREBASE_OBJ.change_value(key=f'vehicles/{vehicle_id}',
                                             subkey='states',
                                             val=current_states)

    return set_response


def build_subscriber_name(sender, token, vehicle_id=None):
    if sender == "app":
        return f"sub_{token}_{vehicle_id}"
    elif sender == "vehicle":
        return f"sub_{token}_app"
    return False


def build_publisher_name(token):
    return f"pub_{token}"


# Temporary, we shouldn't keep this long term
@spicy_api.route("/get_full_database", methods=['GET'])
def index():
    return FIREBASE_OBJ.get_data()


# Revoke a token (Should be done on logout)
@spicy_api.route("/revoke_token", methods=['POST'])
def revoke_token():
    """
    post_request sample: {
        "token": "token",
    }

    :return:
    """
    post_request = request.json
    try:
        user = get_user(post_request['token'])
    except KeyError:
        return "Error: Missing login token."
    # TODO Revoke the token
    # Return an empty json object to indicate success
    return {}


# Verify that your token is still valid
@spicy_api.route("/verify_token", methods=['POST'])
def verify_token():
    """
    post_request sample: {
        "token": "token",
    }

    :return:
    """
    post_request = request.json
    try:
        user = get_user(post_request['token'])
    except KeyError:
        raise KeyError("VerifyToken: Missing login token.")
    if user is None:
        raise ValueError("VerifyToken: Invalid login token.")
    # Return an empty json object to indicate success
    return "{}"


# Attempt to log in to the server, returns the error message if it fails or the provided credentials are invalid
@spicy_api.route("/attempt_login", methods=['POST'])
def attempt_login():
    """
    post_request sample: {
        "username": "username",
        "password": "password",
    }

    :return:
    """
    post_request = request.json

    try:
        username = post_request['username']
        password = post_request['password']
    except KeyError:
        raise KeyError("Error: Missing username or password.")

    if password is None or username is None:
        raise ValueError("Error: Missing username or password.")

    user = FIREBASE_OBJ.get_data(key=f'users',
                                 subkey=encode(username))

    if user is None:
        raise ValueError("Invalid username or password.")

    if str(hash_string_with_salt(password, user['salt'])) == user['password']:
        token = gen_token()
        hashed_token = str(hash_string_with_salt(token, user['salt']))
        # Attempt to store hashed_token in the database as one of the user's tokens. This should be tested.
        FIREBASE_OBJ.add_value(key=f'users/{encode(username)}', subkey='token', val=hashed_token)
        return {"token": f"{token}"}
    else:
        raise ValueError("Invalid password.")


def gen_token():
    possible_chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join(random.choice(possible_chars) for i in range(random.randint(25, 35)))


def hash_string_with_salt(input_string, salt):
    if isinstance(input_string, str):
        input_string = input_string.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', input_string, salt, 100000)


def get_user(token):
    if token is None:
        return None

    users = FIREBASE_OBJ.get_data(key=f'users')

    for user in users.keys():
        hashed_token = str(hash_string_with_salt(token, users[user]['salt']))
        # Look through all users for the user holding the passed in token
        try:
            if users[user]['token'] == hashed_token:
                return users[user]
        except KeyError:
            continue

    return None


def can_access_vehicle(user, vehicle_id):
    print(vehicle_id)
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


@spicy_api.route("/get_vehicle_id", methods=['POST'])
def get_vehicle_ids():
    """
    post_request sample: {
        "token": "token",
    }

    :return:
    """
    post_request = request.json
    try:
        user = get_user(post_request['token'])
    except KeyError:
        return "Error: Missing login token."

    # noinspection PyTypeChecker
    return user['vehicle']


@spicy_api.route("/get_vehicle_data", methods=['POST'])
def get_vehicle_data():
    """
    post_request sample: {
        "token": "token",
        "vehicle_id": "vehicle1",
    }

    :return:
    """
    post_request = request.json
    try:
        user = get_user(post_request['token'])
    except KeyError:
        return "Error: Missing login token."

    logging.info(f'Getting vehicle data')

    try:
        vehicle_id = post_request['vehicle_id']
    except KeyError:
        return "Error: No vehicle id provided."

    if vehicle_id is None or vehicle_id == "":
        logging.error('No vehicle id provided.')
        return "Error: No vehicle id provided."

    if can_access_vehicle(user, vehicle_id):
        vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                             subkey=vehicle_id)

        if vehicle_data is None:
            return f"Error: No vehicle data found for {vehicle_data}."

        return vehicle_data
    else:
        return "Error: You are not authorized to view this vehicle's data"


@spicy_api.route("/set_val", methods=['POST'])
def set_val():
    """
    Example POST Request
    post_request = {
        "token": "token",
        "vehicle_id": "string",
        "key": "string",
        "subkey": "string",  # Optional
        "new_val": bool,
        "sender": "string" # app or device
    }
    :return: bool indicating whether or not the update was successful
    """
    post_request = request.json

    vehicle_id = post_request['vehicle_id']
    key = post_request['key']
    new_val = post_request['new_val']
    sender = post_request['sender']
    token = post_request['token']

    try:
        subkey = post_request['subkey']
    except KeyError:
        subkey = None

    try:
        user = get_user(post_request['token'])
    except KeyError:
        return "False"

    if can_access_vehicle(user, vehicle_id):
        publisher = Publisher(PROJECT_ID, TOPIC_NAME)
        # build the subscriber name
        sub_name = build_subscriber_name(sender, token, vehicle_id)
        # check if the request is to turn off the car
        if key == 'carOn' and new_val is False:
            set_response = turn_off_vehicle(vehicle_id)

            if set_response is None:
                return "False"
            else:
                vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                                     subkey=vehicle_id)

                # Assumes that the subscribers already exist
                publisher.publish_message(vehicle_data['states'], recipient=sub_name)

                return f"Sending message to {sub_name}"

        response = FIREBASE_OBJ.change_value(key=f"vehicles/{vehicle_id}/states/{key}",
                                             subkey=subkey,
                                             val=new_val)

        vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                             subkey=vehicle_id)

        if response is None:
            return "False"
        else:
            publisher.publish_message(vehicle_data['states'], recipient=sub_name)

            logging.info(f"Alerting {sub_name} of {sender}\'s changes")

            return f"Sending message to {sub_name}"
    else:  # Cannot access vehicle
        return "False"


if __name__ == "__main__":
    spicy_api.run(debug=True, host='0.0.0.0', port="8080")
