import os
import sys
import yaml

config = None

config_folder = os.path.dirname(os.path.realpath(__file__))

# TODO: fix this
with open(config_folder + "/../config.yml", 'r') as stream:
    try:
        config = yaml.load(stream)
    except yaml.YAMLError as e:
        # logger is not yet loaded, print it roughly
        print('[!][%s] %s' % ('config', e))

base_path = os.path.expanduser(config["base_path"])

if not os.path.isdir(base_path):
    os.makedirs(base_path)


