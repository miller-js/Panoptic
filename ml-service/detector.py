'''
This file knows everything about machine learning.

It doesn't know Elasticsearch exists.

It just receives Python dictionaries and returns predictions.

'''

# Helper function to safely retrieve nested fields
def get_nested(data, *keys, default=None):
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current