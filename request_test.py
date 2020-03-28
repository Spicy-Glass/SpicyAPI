import requests
import json


class SpicyApiTest:
    def __init__(self, url='http://localhost:8080/'):
        self.url = url

    def get_vehicle_id_test(self):
        # Construct the URL and message to send to the microservice
        endpoint = self.url+'get_vehicle_id'
        json_message = {
            "username": "michael.bishop@ttu.edu",
            "password": "blah"
        }

        print("\n          /get_vehicle_id Test           \n")

        # Using the requests library, send a POST request with the following
        # message to the URL.
        response = requests.post(url=endpoint,
                                 json=json_message)

        # Extract the status code and returned text
        status_code = response.status_code
        response_body = response.text

        if status_code == 200:
            print("Test Passed!")
            print(f"response: {response_body}\n")
        else:
            print(f"Test Failed with {status_code} status code.")
            print(f"response: {response_body}\n")

        try:
            id_dict = json.loads(response_body)
            return list(id_dict.values())
        except ValueError:
            return [response_body]
        except Exception as e:
            return f"Unexpected data type: {type(response_body)} with Exception: {e}"

    def get_vehicle_data_test(self, vehicle_id):
        endpoint = self.url+"get_vehicle_data"
        message = {
            "vehicle_id": vehicle_id
        }

        response = requests.post(url=endpoint,
                                 json=message)

        # Extract the status code and returned text
        status_code = response.status_code
        response_body = response.text
        vehicle_data = json.loads(response_body)

        if status_code == 200:
            print("Test Passed!")
            print(f"response: {response_body}\n")
        else:
            print(f"Test Failed with {status_code} status code.")
            print(f"response: {response_body}\n")

        return vehicle_data

    def set_val_test(self, message):
        endpoint = self.url + "set_val"

        response = requests.post(url=endpoint,
                                 json=message)

        # Extract the status code and returned text
        status_code = response.status_code
        response_body = response.text

        if status_code == 200:
            print("Test Passed!")
            print(f"response: {response_body}\n")
        else:
            print(f"Test Failed with {status_code} status code.")
            print(f"response: {response_body}\n")


if __name__ == "__main__":
    test_obj = SpicyApiTest()
    vehicle_id_list = test_obj.get_vehicle_id_test()

    print(f"Vehicle IDs: {vehicle_id_list}")

    dict1 = {
        "vehicle_id": "V-1",
        "key": "carLock",
        "subkey": None,
        "new_val": False,
        "sender": "app",
        "token": "asdfjfdklsjdjdyebv"
    }

    # dict2 = {
    #     "vehicle_id": "V-2",
    #     "key": "seatHeater",
    #     "subkey": "fDriver",
    #     "new_val": True,
    #     "sender": "vehicle",
    #     "token": "asdfjfdklsjdjdyebv"
    # }

    test_obj.set_val_test(message=dict1)
    # test_obj.set_val_test(message=dict2)
