from google.cloud import pubsub_v1
import time
import json


class Subscriber:
    def __init__(self, project_id, subscriber, topic_name):
        self._subscriber_obj = pubsub_v1.SubscriberClient()
        self.project_id = project_id
        self.subscriber_name = subscriber
        self.topic_name = topic_name
        self.project = self.get_project(project_id)
        self.subscriber = self.get_subscriber(project_id, subscriber)
        self.initial_check()

    def initial_check(self):
        subscriptions_iterator = self.get_subscriptions()
        subscriptions_list = []

        for sub in subscriptions_iterator:
            subscriptions_list.append(sub.name)

        # print(f"Subscriber path: {self.subscriber}")
        # print(f"All subscriptions: {subscriptions_list}")

        if self.subscriber not in subscriptions_list:
            print(f"Creating {self.subscriber}")
            print(f"Subscriptions: {subscriptions_list}")
            # self.create_subscriber(self.subscriber_name)

    def get_project(self, project_id):
        """

        This function returns the entire project path by using the project id

        :param project_id: project identifier corresponding to the project
        containing the desired subscriber
        :return:
        """
        return self._subscriber_obj.project_path(project_id)

    def get_subscriber(self, project_id, subscriber):
        """

        This function returns the entire subscriber path by using the
        project id and subscriber name

        :param project_id: project identifier corresponding to the project
        containing the desired subscriber
        :param subscriber: name of the subscriber that you want to pull
        messages from
        :return:
        """
        return self._subscriber_obj.subscription_path(
                project_id, subscriber
            )

    def get_subscriptions(self):
        return self._subscriber_obj.list_subscriptions(self.project)

    def create_subscriber(self, name):
        subscriber_path = self._subscriber_obj.subscription_path(
            self.project_id, name
        )
        topic_path = self._subscriber_obj.topic_path(
            self.project_id, self.topic_name
        )

        self._subscriber_obj.create_subscription(subscriber_path, topic_path)

    def callback(self, message):
        """

        This function will be called every time a new message is pulled from
        the queue.

        :param message: object containing information about the incoming
        message
        :return:
        """
        # print(f"Received message: {message.data}\n")
        decoded_message = message.data.decode("utf-8")
        try:
            message_dict = json.loads(decoded_message)
            recipient = message.attributes['recipient']
            # print(f"recipient = {recipient}\n")
            # print(f"message_dict = {message_dict}\n")

            if recipient == self.subscriber_name:
                print("Message is meant for this subscriber!\n")
                print(f"message_dict = {message_dict}\n")
                print(f"recipient = {recipient}\n")
        except Exception as e:
            print(f"{decoded_message} was not a string dictionary.")
            print(f"Exception: {e}")

        message.ack()

    def start_server(self):
        """

        This function will indefinitely pull messages from the queue sent to
        the previously selected subscriber.

        :return:
        """
        print(f"Listening for messages on {self.subscriber}")
        print("...")
        while True:
            streaming_pull_future = self._subscriber_obj.subscribe(
                self.subscriber, callback=self.callback
            )

            try:
                streaming_pull_future.result(timeout=4)
            except KeyboardInterrupt:
                streaming_pull_future.cancel()
                print("Exiting Gracefully")
                break
            except:
                # print(f"Exception: {e}")
                streaming_pull_future.cancel()

            time.sleep(5)
