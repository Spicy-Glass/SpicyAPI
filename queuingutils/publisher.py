from google.cloud import pubsub_v1


class Publisher:
    def __init__(self, project_id, topic_name):
        self._publisher_obj = pubsub_v1.PublisherClient()
        self.project_id = project_id
        self.topic_name = topic_name
        self.project = self.get_project(project_id)
        self.topic = self.get_topic(project_id, topic_name)
        self.initial_check()

    def initial_check(self):
        topics_iterator = self.get_topics()
        topics_list = []

        for topic in topics_iterator:
            topics_list.append(topic.name)

        if self.topic not in topics_list:
            self.create_topic(self.topic)

    def publish_message(self, message, metadata):
        import json

        string_metadata = json.dumps(metadata)

        self._publisher_obj.publish(self.topic,
                                    message,
                                    metadata=string_metadata)

    def create_topic(self, topic_name):
        response = self._publisher_obj.create_topic(topic_name)

        return response

    def delete_topic(self, topic_name):
        self._publisher_obj.delete_topic(topic_name)

    def get_topic(self, project_id, topic_name):
        topic = self._publisher_obj.topic_path(project_id,
                                               topic_name)
        return topic

    def get_topics(self):
        return self._publisher_obj.list_topics(self.project)

    def get_project(self, project_id):
        return self._publisher_obj.project_path(project_id)

    def get_subscriptions(self):
        return self._publisher_obj.list_topic_subscriptions(self.topic)
