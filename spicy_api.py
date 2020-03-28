from flask import Flask, request
from firebase_interface import FirebaseInterface
from queuingutils.publisher import Publisher
from queuingutils.subscriber import Subscriber
import json

spicy_api = Flask(__name__)

with open("creds.json") as file:
    creds = json.load(file)

FIREBASE_OBJ = FirebaseInterface(creds_dict=creds)
PROJECT_ID = 'pub-sub132608'
TOPIC_NAME = 'api-pub'


def encode(raw_string):
    encoded_string = raw_string.replace(".", "_DOT_")
    return encoded_string


def decode(encoded_string):
    raw_string = encoded_string.replace("_DOT_", ".")
    return raw_string


def turn_off_vehicle(id):
    # retrieve the data corresponding to the desired vehicle
    vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                         subkey=id)

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
    set_response = FIREBASE_OBJ.change_value(key=f'vehicles/{id}',
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


@spicy_api.route("/get_full_database", methods=['GET'])
def index():
    return FIREBASE_OBJ.get_data()


@spicy_api.route("/get_vehicle_id", methods=['POST'])
def user_info():
    post_request = request.json
    username = None
    password = None

    try:
        username = post_request['username']
        password = post_request['password']
    except KeyError:
        return "Error: Missing required key value pair."

    if password is None:
        if username is None:
            return "Error: password and username keys have no values."
        return "Error: password key has no value."

    if username is None:
        return "Error: username key has no value."

    user = FIREBASE_OBJ.get_data(key=f'users',
                                 subkey=encode(username))

    if user is None:
        return f"Error: username {username} not found."

    if password == user['password']:
        return user['vehicle']
        # return user
    else:
        return "Fetch Unsuccessful: Invalid Password"


@spicy_api.route("/get_vehicle_data", methods=['POST'])
def get_vehicle_data():
    """

    post_request sample: {
        "vehicle_id": "vehicle1",
    }

    :return:
    """

    post_request = request.json

    try:
        vehicle_id = post_request['vehicle_id']
    except KeyError:
        return "Error: vehicle_id key not provided in POST request."

    if vehicle_id is None or vehicle_id == "":
        return "Error: No vehicle id provided."

    vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                         subkey=vehicle_id)

    if vehicle_id is None:
        return f"Error: No vehicle data found for {vehicle_id}."

    return vehicle_data


@spicy_api.route("/set_val", methods=['POST'])
def set_val():
    """

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

    vehicle_id = post_request['vehicle_id']
    key = post_request['key']
    new_val = post_request['new_val']
    sender = post_request['sender']
    token = post_request['token']

    publisher = Publisher(PROJECT_ID, TOPIC_NAME)

    # build the subscriber name
    sub_name = build_subscriber_name(sender, token, vehicle_id)

    try:
        subkey = post_request['subkey']
    except KeyError:
        subkey = None

    # check if the request is to turn off the car
    if key == 'carOn' and new_val == False:
        set_response = turn_off_vehicle(vehicle_id)

        if set_response is None:
            return "False"
        else:
            vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                                 subkey=vehicle_id)

            string_dict = json.dumps(vehicle_data)

            # Assumes that the subscribers already exist
            publisher.publish_message(sub_name.encode("utf-8"),
                                      string_dict)

            return f"Sending message to {sub_name}"

    response = FIREBASE_OBJ.change_value(key=f"vehicles/{vehicle_id}/states/{key}",
                                         subkey=subkey,
                                         val=new_val)

    vehicle_data = FIREBASE_OBJ.get_data(key=f'vehicles',
                                         subkey=vehicle_id)

    string_dict = json.dumps(vehicle_data)

    if response is None:
        return "False"
    else:
        publisher.publish_message(sub_name.encode("utf-8"),
                                  string_dict)

        return f"Sending message to {sub_name}"


if __name__ == "__main__":
    spicy_api.run(debug=True, host='0.0.0.0', port="8080")

