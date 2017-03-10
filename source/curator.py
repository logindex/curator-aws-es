import base64
import logging
import re
import sys
from collections import defaultdict

import boto3
from aws_requests_auth.aws_auth import AWSRequestsAuth
from elasticsearch import Elasticsearch
from elasticsearch import RequestsHttpConnection

REGION_REGEXP = '.+\.([^\.]+)\.es\.amazonaws\.com$'

logging.basicConfig(stream=sys.stdout, level=logging.WARN)

PATTERNS = {
    'OneHour': '.*\d{4}-\d{2}-\d{2}-\d{2}$',
    'OneDay': '.*\d{4}-\d{2}-\d{2}$',
    'OneWeek': '.*\d{4}-w\d{2}$',
    'OneMonth': '.*\d{4}-\d{2}$',
}


class CuratorAwsEs:
    def __init__(self, config):
        self.config = config
        self.kms = boto3.client('kms')
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(level=logging.INFO)

    def curate(self):

        deleted = defaultdict(list)

        # Looping from the clusters defined in config file
        for cluster_config in self.config:
            cluster_name = cluster_config['name']

            # Get a client to talk to private AWS Elasticsearch instance
            es = self.get_es_client(cluster_config)

            # Iterate over indices to curate
            for index in cluster_config['indices']:
                prefix = index['prefix']
                keep = index['keep']
                rotation = index['rotation']
                indexes = sorted([i for i in es.indices.get(prefix + '*') if self.index_matches(i, rotation)])

                self.logger.info("Found {} indices on cluster '{}' with prefix '{}', rotation '{}'".format(indexes,
                                                                                                           cluster_name,
                                                                                                           prefix,
                                                                                                           rotation))

                if len(indexes) <= keep:
                    self.logger.info("There are no indices to delete at this time. Prefix: '{}', count: {}, keep: {}"
                                     .format(prefix,
                                             len(indexes),
                                             keep))

                for index_to_delete in indexes[0:len(indexes) - keep]:
                    try:
                        self.logger.info("Deleting: {}".format(index_to_delete))
                        es.indices.delete(index_to_delete)
                        deleted[cluster_name].append(index_to_delete)
                    except:
                        self.logger.error("Error occurred while deleting index '{}'".format(index_to_delete))

        for cluster_name in deleted.keys():
            self.logger.info("Deleted {} indices from cluster '{}'".format(deleted[cluster_name], cluster_name))

    def get_es_client(self, cluster_config):
        """
        Resolves elasticsearch client for AWS managed elasticsearch instance key/secret restricted
        :param cluster_config: cluster connectivity details
        :return: Elasticsearch client
        """
        host = cluster_config['endpoint']
        aws_access_key_cipher = cluster_config['access_key_cipher']
        aws_secret_access_key_cipher = cluster_config['access_secret_cipher']
        region = self.infer_region(host)

        aws_access_key = self.decrypt_cipher(aws_access_key_cipher)
        aws_secret_access_key = self.decrypt_cipher(aws_secret_access_key_cipher)

        auth = AWSRequestsAuth(aws_access_key=aws_access_key,
                               aws_secret_access_key=aws_secret_access_key,
                               aws_host=host,
                               aws_region=region,
                               aws_service='es')
        es = Elasticsearch(
            hosts=[{'host': host, 'port': 443}],
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
            http_auth=auth,
            timeout=300,
        )

        return es

    @staticmethod
    def index_matches(index, rotation):
        pattern = PATTERNS[rotation]
        return re.match(pattern, index)

    @staticmethod
    def infer_region(host):
        """
        Infers AWS region from Elasticsearch host address
        :param host: host address
        :return: AWS region
        """
        m = re.match(REGION_REGEXP, host)
        if m:
            return m.group(1)
        raise ValueError("AWS region cannot be inferred from host: '{}'".format(host))

    def decrypt_cipher(self, cipher):
        """
        Decrypts a cipher, encrypted with a KMS key.
        :param cipher: The blob to decrypt. Can be a file object, a string (base64 encoded) or a binary object
        :return: The binary buffer that was decrypted or None if it failed
        """
        cipher = base64.b64decode(cipher)
        response = self.kms.decrypt(CiphertextBlob=cipher)
        return response.get('Plaintext').decode()
