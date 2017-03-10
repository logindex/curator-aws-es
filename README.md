# curator-aws-es
Lambda function to curate time-rotated indices created by Firehose on AWS managed Elasticsearch

**curator-aws-es** assumes indices are created by Firehose and follow its naming convention:
http://docs.aws.amazon.com/firehose/latest/dev/basic-deliver.html#es-index-rotation

Adjust source/config.yaml for your needs and execute package.py in order to build an AWS Lambda package.
Upload the zip package to S3 and create AWS Lambda pointing to a zip and specifying curator-aws-es.lambda_handler as handler.

**Note**
Make sure you reviewed the config.yaml as indices will be permanently deleted
