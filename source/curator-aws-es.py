import yaml

from curator import CuratorAwsEs


def lambda_handler(event, context):

    with open('config.yaml') as config_file:
        config = yaml.load(config_file)

    curator = CuratorAwsEs(config)
    curator.curate()

if __name__ == '__main__':
    lambda_handler(None, None)