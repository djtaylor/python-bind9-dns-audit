import re
import json
from collections import namedtuple

def merge_dict(a, b, path=None):
        """
        Merge two dictionaries together. Do not overwrite duplicate keys.

        :param a: The first dictionary
        :type a: dict
        :param b: The second dictionary
        :type b: dict
        :param path: Prepend optional path to the dict structure
        :type path: list
        """
        if path is None: path = []
        for key in b:
            if key in a:
                if isinstance(a[key], dict) and isinstance(b[key], dict):
                    merge_dict(a[key], b[key], path + [str(key)])
                elif a[key] == b[key]:
                    pass
                else:
                    raise Exception('Conflict at {0}'.format('.'.join(path + [str(key)])))
            else:
                a[key] = b[key]
        return a

class Collection(object):
    """
    Construct an immutable collection from a dictionary.
    """
    def __init__(self, init_data=None):
        """
        Initialize a new collection object.

        :param init_data: An optional dictionary used to initialize the collection
        :type init_data: dict
        """
        self.class_name = self.__class__.__name__
        if init_data:
            if isinstance(init_data, dict):
                self.collection = init_data
            else:
                self.collection = {}
        else:
            self.collection = {}

    def map(self, map_dict={}):
        """
        Map a dictionary to an existing collection object.

        Mapping a new dictionary object::

            # Import the collection class
            from rancher2.common.collection import Collection

            # Create a collection object
            collection = Collection({'data': {'key1': 'value1'}})

            # Map a new dictionary
            collection.map({'data': {'key2': 'value2'}})

        The new dictionary::

            {
                'data': {
                    'key1': 'value1',
                    'key2': 'value2'
                }
            }

        :param map_dict: The dictionary object to map
        :type map_dict: dict
        """
        if not map_dict:
            return False
        else:
            self.collection = merge_dict(map_dict, self.collection)
            return True

    def get(self):
        """
        Retrieve the constructed collection objects. Converts the internal
        dictionary collection to a named tuple.

        Constructing a collection::

            # Import the collection class
            from rancher2.common.collection import Collection

            # Create a collection object
            collection = Collection()

            # Map collection data
            collection.map({'key1': {'subkey1': 'value1', 'subkey2': 'value2'}})

            # Get the named tuple
            newcol = collection.get()

        Accessing collection data::

            # Get subkey2
            new_var = newcol.key1.subkey2

        :rtype: namedtuple
        """
        def obj_mapper(d):
            """
            Map a dictionary to a named tuple object based on dictionary keys

            :param d: The dictionary to map
            :type d: dict
            :rtype: namedtuple
            """
            return namedtuple(self.class_name, d.keys())(*d.values())

        # Map the data to an object and return
        data = json.dumps(self.collection)
        return json.loads(data, object_hook=obj_mapper)

    @classmethod
    def create(cls, data):
        """
        Create a new collection.

        :param data: The source dictionary
        :type  data: dict
        :rtype: namedtuple
        """
        return cls(data).get()
