import os
import json
import boto3
import re
from google.oauth2 import service_account
from google.cloud import vision


def extract_text_from_image(image_path, credentials):
    """Extract text from image using Google Cloud Vision API"""
    client = vision.ImageAnnotatorClient(credentials=credentials)
    with open(image_path, 'rb') as image_file:
        content = image_file.read()

    image = vision.Image(content=content)
    response = client.text_detection(image=image)
    texts = response.text_annotations[0]

    return texts.description if texts else ""


def detect_pii_with_comprehend(text, region):
    """Detect PII using AWS Comprehend"""
    comprehend = boto3.client('comprehend', region_name=region)

    response = comprehend.detect_pii_entities(Text=text, LanguageCode='en')

    entities = [entity for entity in response['Entities']
                if entity['Type'] != 'IP_ADDRESS']
    return entities


def redact_pii(text, pii_entities):
    """Redact PII from the text, including lines matching asterisks and numbers"""
    # Define the regex pattern to match lines with asterisks followed by numbers
    pattern = re.compile(r'.*\*+\d+', re.MULTILINE)
    # Remove lines matching the pattern
    text = pattern.sub('[REDACTED LINE]', text)
    # Initialize redacted text
    redacted_text = text
    if pii_entities:
        for entity in sorted(pii_entities, key=lambda x: x['BeginOffset'], reverse=True):
            start = entity['BeginOffset']
            end = entity['EndOffset']
            redacted_text = redacted_text[:start] + \
                f"[REDACTED {entity['Type']}]" + redacted_text[end:]
    return redacted_text


def get_secret(secret_name, region):
    """Get secret from google cloud api access from environment variables"""
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager', region_name=region)

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name)
        secret = get_secret_value_response['SecretString']
        return json.loads(secret)
    except Exception as e:
        raise e


def download_photo(event, region):
    try:
        # Extract bucket name and object key from the event
        bucket_name = event['Records'][0]['s3']['bucket']['name']
        object_key = event['Records'][0]['s3']['object']['key']

        # Define the path to download the file in Lambda's temporary storage
        download_path = f'/tmp/{os.path.basename(object_key)}'

        s3_client = boto3.client('s3', region_name=region)

        # Check if the object exists
        try:
            s3_client.head_object(Bucket=bucket_name, Key=object_key)
            print(f"Object {object_key} exists in bucket {bucket_name}")
        except ClientError as e:
            if e.response['Error']['Code'] == "404":
                print(f"Object {object_key} does not exist in bucket {
                      bucket_name}")
                return None
            else:
                print(f"Error checking object existence: {str(e)}")
                raise

        # Download the photo from S3
        s3_client.download_file(bucket_name, object_key, download_path)
        print(f"Successfully downloaded file to {download_path}")
        return download_path
    except Exception as e:
        print(f"Error in download_photo function: {str(e)}")
        return None


def lambda_handler(event, context):
    secret_name = os.environ['SECRET_NAME']
    # AWS Lambda provides this automatically
    region = os.environ['AWS_REGION']
    # Get Google Cloud credentials from Secrets Manager
    credentials_dict = get_secret(secret_name, region)

    # Use the credentials to authenticate
    credentials = service_account.Credentials.from_service_account_info(
        credentials_dict)

    download_path = download_photo(event, region)

    extracted_text = extract_text_from_image(download_path, credentials)
    print("Text Extracted")

    pii_entities = detect_pii_with_comprehend(extracted_text, region)
    print("\nDetected PII Ententies:")

    # Redact PII from the text
    redacted_text = redact_pii(extracted_text, pii_entities)
    return {
        'statusCode': 200,
        'body': json.dumps({'redacted_text': redacted_text})
    }
