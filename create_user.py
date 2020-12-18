import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import json
from random import choice
import string

USER_POOL_ID = ''
CLIENT_ID = ''
CLIENT_SECRET = ''

def get_secret_hash(username):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'), 
        msg = str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2



def lambda_handler(event, context):
    for field in ["username", "email", "password", "name"]:
        if not event.get(field):
            return {"error": False, "success": True, 'message': f"{field} is not present", "data": None}
    username_req = event['username']
    email = event["email"]
    password = event['password']
    name = event["name"]
    client = boto3.client('cognito-idp')


    valores = string.ascii_letters + string.digits + string.punctuation
    senha = ''
    for i in range(8):
        senha += choice(valores)

    try:
        resp = client.admin_create_user(
            UserPoolId= USER_POOL_ID,
            SecretHash=get_secret_hash(username_req),
            Username= username_req,
            UserAttributes=[
                {
                    'Name': "name",
                    'Value': name
                },
                {
                    'Name': "email",
                    'Value': email
                },
            ],
            ValidationData=[
                {
                    'Name': "email",
                    'Value': email
                },
                {
                    'Name': "custom:username",
                    'Value': username_req
                },
            ],
            TemporaryPassword= senha,
            ForceAliasCreation=True,
            MessageAction='RESEND',
            DesiredDeliveryMediums=[
                'EMAIL',
            ],
            ClientMetadata={
                'string': 'string'
            }
        )
        resp_group = client.admin_add_user_to_group(
            UserPoolId= USER_POOL_ID,
            Username= username_req,
            GroupName='string'
        )

        resposta  =  client.admin_confirm_sign_up ( 
            UserPoolId = USER_POOL_ID , 
            Username = username_req , 
            ClientMetadata = { 
                'string' :  'string' 
            } 
        )
            
    
    except client.exceptions.UsernameExistsException as e:
        return {"error": False, 
               "success": True, 
               "message": "This username already exists", 
               "data": None}
    except client.exceptions.InvalidPasswordException as e:
        
        return {"error": False, 
               "success": True, 
               "message": "Password should have Caps,\
                          Special chars, Numbers", 
               "data": None}
    except client.exceptions.UserLambdaValidationException as e:
        return {"error": False, 
               "success": True, 
               "message": "Email already exists", 
               "data": None}
    
    except Exception as e:
        return {"error": False, 
                "success": True, 
                "message": str(e), 
               "data": None}
    
    return {"error": False, 
            "success": True, 
            "message": "Please confirm your signup, \
                        check Email for username and password", 
            "data": None}