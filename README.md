# SpicyAPI
This API will be responsible for handling requests from the Spicy Glass mobile
app as well as the Raspberry Pi that is representing a car for our project and 
allow those uncoupled entities to make changes to our Firebase database storing
all car and user related information. The user will have the power to retrieve 
as well as change data using this API. 

## Getting Started

The following instructions will cover how to download and run a local 
deployment of the SpicyAPI with minimal dependencies.

### Prerequisites

You will need to first download the SpicyAPI repository from GitHub. To do so, 
type the following command in the terminal.

```
https://github.com/Spicy-Glass/SpicyAPI.git
```

The API runs on Python 3.7. So, if you don't have it, download a version 
[here](https://www.python.org/downloads/).

### Installing

We made installing dependencies for the development environment simple and 
easy. Here are the dependencies for SpicyAPI local.

* Flask
* requests

Just install the packages on our requirements.txt:

```
pip install -r requirements.txt
```

The API is run using Flask and is hosted on your local port 8080. Make sure 
that port is clear when running the program.

To run the API, type the following command:

```
python spicy_api.py
```

If everything runs properly, you should see this in your terminal.

```
 * Serving Flask app "spicy_api" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: on
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 271-809-182
 * Running on http://0.0.0.0:8080/ (Press CTRL+C to quit)

```

Once the API is up on running, like shown above, you can start making requests
to the different routes that are available

### Routes
* /
* /get_full_database
* /verify_token
* /revoke_token
* /get_vehicle_id
* /get_vehicle_data
* /set_val

**"/"**

Request Type: GET

Expected Input: NONE

Output: Table of contents containing routes and a link to the API's
Postman documentation.

```html
<h1>Spicy API</h1>
<h3>Routes</h3>
<ul>
  <li>revoke_token</li> 
  <li>verify_token</li>
  <li>attempt_login</li>
  <li>get_vehicle_ids</li>
  <li>get_vehicle_data</li>
  <li>set_val</li>
</ul>
<p>Docs <a href="link">here</a></p>
```

On your Flask terminal where you ran the API, something like this should appear:

```
127.0.0.1 - - [20/Mar/2020 23:00:25] "GET / HTTP/1.1" 200 -
```

**Get Full Database**

Retrieves the entire database from Firebase.

Request Type: GET

Expected Input: NONE

Output: Dictionary with the contents of the whole Database

```
{
  "users": {
    "john_DOT_smith@gmail_DOT_com": {
      "password": "password", 
      "vehicle": "V-1"
    }, 
    "jane_DOT_doe@yahoo_DOT_com": {
      "password": "password", 
      "vehicle": {
        "V1": "V-1", 
        "V2": "V-2"
      }
    }
  }, 
  "vehicles": {
    "V-1": {
      "description": {
        "make": "Nissan", 
        "model": "Maxima", 
        "type": "sedan", 
        "year": "2007"
      }, 
      "states": {
        "carLock": false, 
        "carOn": true, 
        "defrost": {
          "back": false, 
          "front": false
        }, 
        "seatHeater": {
          "bDriver": false, 
          "bPass": false, 
          "fDriver": false, 
          "fPass": false
        }
      }
    }, 
    "V-2": {
      "description": {
        "make": "Ford", 
        "model": "Focus", 
        "type": "sedan", 
        "year": "2000"
      }, 
      "states": {
        "carLock": true, 
        "carOn": true, 
        "defrost": {
          "back": false, 
          "front": false
        }, 
        "seatHeater": {
          "bDriver": false, 
          "bPass": false, 
          "fDriver": false, 
          "fPass": false
        }
      }
    }
  }
}

```

On your Flask terminal where you ran the API, something like this should appear:

```
127.0.0.1 - - [20/Mar/2020 22:45:20] "GET /get_full_database HTTP/1.1" 200 -
```

**Verify Token**

Verifies that the token passed in exists in the database.

Request Type: POST

Expected Input: Dictionary containing the client's unique token

```
{
    "token": "YOUR_TOKEN"
}
```

Output: Dictionary of vehicle ID's corresponding to that user

```
{
    "success": true
}
```

On your Flask terminal where you ran the API, something like this should appear:

```
127.0.0.1 - - [20/Mar/2020 22:45:20] "POST /verify_token HTTP/1.1" 200 -
```

**Revoke Token**

Removes the token from the database.

Request Type: POST

Expected Input: Dictionary containing the client's unique token

```
{
    "token": "YOUR_TOKEN"
}
```

Output: Dictionary of vehicle ID's corresponding to that user

```
{
    "success": true
}
```

On your Flask terminal where you ran the API, something like this should appear:

```
127.0.0.1 - - [20/Mar/2020 22:45:20] "POST /revoke_token HTTP/1.1" 200 -
```

**Get Vehicle ID**

Retrieves all of the user's vehicle ID's

Request Type: POST

Expected Input: Dictionary containing username and password in the following
format

```
{
    "username": "john_DOT_smith@gmail_DOT_com",
    "password": "password"
}
```

Output: Dictionary of vehicle ID's corresponding to that user

```
{
    "V1": "V-1",
    "V2": "V-2"
}
```

On your Flask terminal where you ran the API, something like this should appear:

```
127.0.0.1 - - [20/Mar/2020 23:00:25] "POST /get_vehicle_id HTTP/1.1" 200 -
```

**Get Vehicle Data**

Retrieves all data on a specific vehicle.

Request Type: POST

Expected Input: Dictionary containing the desired vehicle ID

```
{
    "vehicle_id": "V-1"
}
```

Output: Dictionary containing the all information about the desired vehicle

```
{
  "description": {
    "make": "Nissan", 
    "model": "Maxima", 
    "type": "sedan", 
    "year": "2007"
  }, 
  "states": {
    "carLock": false, 
    "carOn": true, 
    "defrost": {
      "back": false, 
      "front": false
    }, 
    "seatHeater": {
      "bDriver": false, 
      "bPass": false, 
      "fDriver": false, 
      "fPass": false
    }
  }
}

```

On your Flask terminal where you ran the API, something like this should appear:

```
127.0.0.1 - - [20/Mar/2020 23:08:32] "POST /get_vehicle_data HTTP/1.1" 200 -
```

**Set Val**

Changes the value of anything in the Firebase database. This will mainly be 
used for changing states of various things on a particular vehicle.

Request Type: POST

Expected Input: Dictionary containing the vehicle whose state you want to 
change, the key and possibly subkey (for defrost and seatHeater), and the 
new value that you want to put there.

```
{
    "vehicle_id": "string",
    "key": "string",
    "subkey": "string",  # Optional
    "new_val": bool
}
```

Output: Bool indicating whether or not the value change was successful

```
True
```

On your Flask terminal where you ran the API, something like this should appear:

```
127.0.0.1 - - [20/Mar/2020 23:08:32] "POST /set_val HTTP/1.1" 200 -
```

## IoT Communication

### Description

This API uses the PubSub queuing service from the Google Cloud Platform to 
communicate back to the hardware devices in the network and the app users
to alert them of state changes in the Database.
 
![Fan out image](images/FanoutExchange.PNG)
(Source: https://www.rabbitmq.com/tutorials/amqp-concepts.html)

Unfortunately, fan out exchanges are the only kind of exchange that we were 
able to implement using this service. Fan out exchanges are such that the 
Publisher (Topic) sends a message to each Subscriptions' individual queue 
associated with that Publisher.

State of the vehicle (Raspberry Pi) and user information from the app are all 
held on the a Firebase Realtime Database.

### Current model

![System Architecture](images/SpicyArchitecture.jpeg)

We have a Publisher on the API that sends out messages to the app when the 
Raspberry Pi makes changes and vice versa. This event-driven model allows for 
minimum requests to the API and Firebase database as well as load on all 
individual parts of the system.

## Deployment

* (Local w/ Flask) This can be run locally at http://localhost:8080/ by running 
the spicy_api.py file.

* (Local w/ Flask & Docker) This contains a Dockerfile that containerizes the API and 
runs it in a Docker container with it's port mapping set up with 
http://localhost:8080/.

* (Cloud - CloudRun) This is set up to be easily deployed on Google Cloud 
Platform's CloudRun. Our most recent version is deployed and running on 
CloudRun currently.

## Built With

* [GitHub](https://www.github.com/) - CI/CD
* [PyCharm](https://www.jetbrains.com/pycharm/download/#section=windows) - The IDE used
* [Google Cloud Platform](https://cloud.google.com/) - Microservice Deployment(Cloud Run), 
Image Registry(GCR), and Communication(PubSub)
* [Firebase](https://firebase.google.com/) - Data Storage(Realtime Database) 
