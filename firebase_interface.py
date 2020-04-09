from firebasemodified import firebase


class FirebaseInterface:
    def __init__(self, creds_dict):
        self.creds_dict = creds_dict
        self.db_url = self.creds_dict['databaseURL']
        self._firebase_obj = self._connect(self.db_url)
        self._database_dict = self.get_data()

    @staticmethod
    def _connect(db_url):
        """
        This function will create a firebase object given a
        database URL essentially establishing a connection
        to the remote DayTuhBass.
        :param db_url: url associated to the database you want to
        connect to
        returns: firebase object associated to the desired database
        """
        firebase_obj = firebase.FirebaseApplication(db_url)

        return firebase_obj

    def reconnect(self, creds_dict):
        """
        This function will update the firebase object with a
        new database url.
        :param creds_dict: dictionary containing credentials required
        for the firebase API.
        returns: Nothing
        """

        self.db_url = creds_dict['databaseURL']
        self._firebase_obj = self._connect(self.db_url)

    def get_database_dict(self):
        return self._database_dict

    def get_data(self, key='', subkey=None):
        """
        This function will perform a GET request on your database
        given a key and subkey.
        :param key:
        :param subkey:
        returns: Either a dictionary or value held at a
        """

        response = self._firebase_obj.get(key, subkey)
        return response

    def change_value(self, key, val, subkey=None):
        """
        This function will change the value at a location specified by the
        key and subkey.
        :param key:
        :param val
        :param subkey
        """

        if subkey is None:
            response = self._firebase_obj.put('', key, val)
        else:
            response = self._firebase_obj.put(key, subkey, val)

        # Update the local database dictionary with the new database.
        self._database_dict = self.get_data()

        return response

    def add_value(self, key, val, subkey=None):
        """
        This function will add a value at a location specified by the
        key and subkey.
        :param key:
        :param val
        :param subkey
        """

        if subkey is None:
            response = self._firebase_obj.put('', key, val)
        else:
            response = self._firebase_obj.put(key, subkey, val)

        # Update the local database dictionary with the new database.
        self._database_dict = self.get_data()

        return response
