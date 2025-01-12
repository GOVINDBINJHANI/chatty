import boto3
import os
from boto3.dynamodb.conditions import Key
import json
from datetime import timedelta , datetime
import uuid


def dynamo_connect():
    AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    REGION_NAME = os.getenv("AWS_REGION")

    dynamodb = boto3.resource(
        'dynamodb',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=REGION_NAME
    )
    return dynamodb


def save_user(user_name, email, pw_hash, is_sso, referral_code, email_verified):
    dynamodb = dynamo_connect()
    users_table = dynamodb.Table("users")
    user_id = str(uuid.uuid4())
    users_table.put_item(
        Item={
            "user-id": user_id,
            "user_name": user_name,
            "email": email,
            "password": pw_hash,
            "is_sso": is_sso,
            "referral_code": referral_code,
            "referral_count": 0,
            "no_of_referred_chatbots": 0,
            "no_of_chatbots": 1,
            "email_verified": email_verified,
            'customer_id': referral_code,
            'user_status': 'Active',
            'is_cancel': False,
            'subscription_id': None,
            'plan_name': None,
            'valid_till': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'no_of_messages': 500,
            'no_of_characters': 10000,
            'hobby': False,
            'created_ts': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }
    )
    return user_id


def email_capturing(email):
    dynamodb = dynamo_connect()
    email_capturing_table = dynamodb.Table("email_capturing")
    email_capturing_id = str(uuid.uuid4())
    email_capturing_table.put_item(
        Item={
            "email_capturing_id": email_capturing_id,
            "email": email,
            'created_ts': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }
    )


def get_user(email):
    dynamodb = dynamo_connect()
    users_table = dynamodb.Table("users")
    response = users_table.query(
        IndexName="email-index",
        KeyConditionExpression=Key('email').eq(email)
    )
    return response['Items']


def get_user_by_referral_code(referral_code):
    dynamodb = dynamo_connect()
    users_table = dynamodb.Table("users")
    response = users_table.query(
        IndexName="referral_code-index",
        KeyConditionExpression=Key('referral_code').eq(referral_code)
    )
    return response['Items']


def save_url(user_id, website_url, file_url, count):
    dynamodb = dynamo_connect()
    url_table = dynamodb.Table("chatbot_meta")
    chatbot_id = str(uuid.uuid4())
    url_table.put_item(
        Item={
            "user_id": user_id,
            "chatbot_id": chatbot_id,
            "website_url": website_url,
            "file_url": file_url,
            "character_count": count,
            'created_ts': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'updated_ts': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }
    )

    return chatbot_id


def chatbot_meta(chatbot_id):
    dynamodb = dynamo_connect()
    data = dynamodb.Table("chatbot_meta")
    response = data.query(
        KeyConditionExpression=Key('chatbot_id').eq(chatbot_id)
    )

    return response["Items"]


def get_chatbot_history(user_id):
    dynamodb = dynamo_connect()
    chats_table = dynamodb.Table("chatbot_meta")
    response = chats_table.query(
        IndexName="user_id-index",
        KeyConditionExpression=Key('user_id').eq(user_id)
    )

    # response = chats_table.query(
    #     KeyConditionExpression=Key('chat-id').eq(chat_id)
    # )
    return response['Items']


def update_chatbot_name(chatbot_id, chatbot_name, total_len):
    dynamodb = dynamo_connect()
    table = dynamodb.Table("chatbot_meta")
    response = table.update_item(
        Key={

            "chatbot_id": chatbot_id
        },
        UpdateExpression='SET #cn = :cn',
        ExpressionAttributeNames={
            '#cn': 'chatbot_name',
            '#cn': 'character_count',
        },
        ExpressionAttributeValues={
            ':cn': chatbot_name,
            ':cn': total_len

        }
    )


def update_chatbot_role(chatbot_id, role):
    dynamodb = dynamo_connect()
    table = dynamodb.Table("chatbot_meta")
    response = table.update_item(
        Key={

            "chatbot_id": chatbot_id
        },
        UpdateExpression='SET #cn = :cn',
        ExpressionAttributeNames={
            '#cn': 'role',
        },
        ExpressionAttributeValues={
            ':cn': role
        }
    )


def update_user(user_id, field_name, field_value):
    dynamodb = dynamo_connect()
    table = dynamodb.Table("users")
    response = table.update_item(
        Key={
            "user-id": user_id
        },
        UpdateExpression='SET #fn = :val',
        ExpressionAttributeNames={
            '#fn': field_name,
        },
        ExpressionAttributeValues={
            ':val': field_value
        }
    )


def get_all_user():
    dynamodb = dynamo_connect()
    table = dynamodb.Table("users")
    response = table.scan()
    return response['Items']


def get_all_data():
    dynamodb = dynamo_connect()
    table = dynamodb.Table("chatbot_meta")
    response = table.scan()
    return response['Items']


def update_user_by_customer_id(customer_id, field_name, field_value):
    dynamodb = dynamo_connect()
    table = dynamodb.Table("users")

    response = table.scan(
        FilterExpression='customer_id = :cid',
        ExpressionAttributeValues={
            ':cid': customer_id
        }
    )

    items = response['Items']
    if len(items) > 0:
        user = items[0]
        user_id = user['user-id']

        response = table.update_item(
            Key={
                "user-id": user_id
            },
            UpdateExpression='SET #fn = :val',
            ExpressionAttributeNames={
                '#fn': field_name,
            },
            ExpressionAttributeValues={
                ':val': field_value
            }
        )
        return response
    else:
        return {"message": "Customer not found"}


def save_chat_history(chatbot_id, chatbot_name, user_email, query, ai_response):
    dynamodb = dynamo_connect()
    chats_table = dynamodb.Table("chatbot_meta")
    response = chats_table.query(
    KeyConditionExpression=Key('chatbot_id').eq(chatbot_id)
    )
    created_ts=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    existing_history = []
    if response['Items']:
        item = response['Items'][0]
        existing_history = item.get('history',[])
        existing_ques_count=item.get('question_count',0)+1
        new_history = dict({"user": {"message": query}, "bot": {"message": ai_response} ,"created_ts" : created_ts })
        existing_history.append(new_history)
        update_chat(chatbot_id,existing_history,existing_ques_count)
    else:
        chat = dict({"user": {"message": query}, "bot": {"message": ai_response},"created_ts" : created_ts})
        update_chat(chatbot_id,[chat],1)    
    return chatbot_id 
    
    
    
def update_chat(chatbot_id,chat,question_count):
    dynamodb = dynamo_connect()
    chats_table = dynamodb.Table("chatbot_meta")
    response = chats_table.update_item(
        Key={

            "chatbot_id": chatbot_id
        },
        UpdateExpression='SET #ch = :ch , #qc=:qc',
        ExpressionAttributeNames={
            '#ch': 'history',
            '#qc':'question_count',
        },
        ExpressionAttributeValues={
            ':ch': chat,
            ':qc':question_count
        }
    )

# save generated question and edit 
def save_questions(chatbot_id,response,user_id):
    dynamodb = dynamo_connect()
    ques_table = dynamodb.Table("suggested_qus")
    
    ques_id = str(uuid.uuid4())
    ques_table.put_item(
        Item = {
            "ques_id": ques_id,
            "chatbot_id": chatbot_id,
            "question": response,
            "user_id":user_id,
            'created_ts':datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }
        )

def del_question(chatbot_id,ques_id):
    dynamodb = dynamo_connect()
    ques_table = dynamodb.Table("suggested_qus")  
    ques_table.delete_item(
        Key={
            "ques_id":ques_id,
            "chatbot_id": chatbot_id             
        }
    )
    
def get_questions(chatbot_id):
    dynamodb = dynamo_connect()
    ques_table = dynamodb.Table("suggested_qus")
    response = ques_table.query(
        IndexName="chatbot_id-index",
        KeyConditionExpression=Key("chatbot_id").eq(chatbot_id) 
    )
    return response['Items']

def get_user_id(email):
    dynamodb = dynamo_connect()
    users = dynamodb.Table("users")

    response = users.query(
        IndexName='email-index',  
        KeyConditionExpression='email = :email',
        ExpressionAttributeValues={':email': email}
    )

    items = response.get('Items', [])
    if items:
        user = items[0]
        return user['user-id']  # Assuming 'user_id' as the attribute name for the user ID
    else:
        return None
    
def store_reset_token(user_id, reset_token):
    dynamodb = dynamo_connect()
    users = dynamodb.Table("users")

    # Update the user's record with the reset token
    response = users.update_item(
        Key={'user-id': user_id},
        UpdateExpression='SET reset_token = :reset_token',
        ExpressionAttributeValues={':reset_token': reset_token}
    )
    
    
def verify_reset_token(reset_token):
    dynamodb = dynamo_connect()
    users = dynamodb.Table("users")

    # Query the table to find the user record with the provided email
    response = users.scan(
        FilterExpression='reset_token = :reset_token',
        ExpressionAttributeValues={':reset_token': reset_token}
    )
    items = response.get('Items', [])
    if items:
        user = items[0]
        # print(user['user-id'])
        # Extract the token and the encoded expiry timestamp
        token, encoded_expiry_timestamp = reset_token.split('-')

        # Convert the encoded expiry timestamp to a datetime object
        expiry_timestamp = float(encoded_expiry_timestamp)
        expiry_time = datetime.fromtimestamp(expiry_timestamp)

        # Check if the token has expired
        current_time = datetime.now()
        if current_time > expiry_time:
            # Token has expired
            # return "Reset token has expired"
            return None
        
        else:
            # Calculate the expiration time for the token (e.g., 24 hours from now)
            token_expiration = current_time - timedelta(hours=24)

            # Update the reset token with the new expiration time
            updated_token = f'{token}-{token_expiration.timestamp()}'
            users.update_item(
                Key={'user-id': items[0]['user-id']},
                UpdateExpression='SET reset_token = :updated_token',
                ExpressionAttributeValues={':updated_token': updated_token}
            )
            return user['user-id']  # Assuming 'user_id' as the attribute name for the user ID
    else:
        # return "Invalid Reset token"
        return None    
    
def update_password(user_id, password):
    dynamodb = dynamo_connect()
    users = dynamodb.Table("users")
    # Update the user's record with the new password
    response = users.update_item(
        Key={'user-id': user_id},
        UpdateExpression='SET password = :password',
        ExpressionAttributeValues={':password': password}
    )

def update_question(ques_id,bot_id,text,source_id):
    dynamodb = dynamo_connect()
    ques_table = dynamodb.Table("suggested_questions")
    resp = ques_table.query(
        KeyConditionExpression=Key('ques_id').eq(ques_id)
    )
    # question=resp['Items'][0]['question']
    response = ques_table.update_item(
        Key={
            "ques_id":ques_id,                
            "bot_id":bot_id
        },
        UpdateExpression='SET #vc = :vc , #vs= :vs',
        ExpressionAttributeNames={
            '#vc': 'question',
            '#vs' :'source_id'
        },
        ExpressionAttributeValues={
            ':vc': text,
            ':vs' :source_id,
        }
    ) 
def get_teams(team_id):
    dynamodb = dynamo_connect()
    team_table = dynamodb.Table("teams")
    response = team_table.query(
        IndexName="team_id-index",
        KeyConditionExpression=Key("team_id").eq(team_id) 
    )
    return response['Items']

def get_all_bots(user_id,team_id):
    dynamodb = dynamo_connect()
    bot_table = dynamodb.Table("bots")
    response = bot_table.query(
        IndexName="team_id-user_id-index",
        KeyConditionExpression=Key("team_id").eq(team_id) & Key("user_id").eq(user_id)
    )
    return response['Items']

def get_page_count(bot_id):
    dynamodb = dynamo_connect()
    doc_table = dynamodb.Table("docsbot_meta")
    response = doc_table.query(
        IndexName="bot_id-index",
        KeyConditionExpression=Key("bot_id").eq(bot_id) 
    )
    items=response['Items']
    page_count=0
    for item in items:
        if item.get('page_count') is not None:
            page_count += item['page_count']

    return page_count


def get_package_data(plan_id):
    dynamodb = dynamo_connect()
    package_table = dynamodb.Table("package")
    response = package_table.query(        
        KeyConditionExpression=Key('plan_id').eq(plan_id) 
    )
    return response['Items'][0]['package_data']

def save_source(source_id,user_id,source_type,source_title,source_url,scheduling,file_url,page_count,bot_id):
    dynamodb = dynamo_connect()
    users_table = dynamodb.Table("docsbot_meta")
    users_table.put_item(
        Item={
            "source_id":source_id,
            "user_id":user_id,
            "source_type":source_type,
            "source_title":source_title,
            "source_url":source_url,
            "scheduling":scheduling,
            "file_url":file_url,
            "page_count":page_count,
            "bot_id":bot_id,
            "job_status" : 'Finished',
            'created_ts':datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }
    )

def update_source_count(chatbot_id, user_id, count):
    dynamodb = dynamo_connect()
    bot_table = dynamodb.Table("bots")  
    response = bot_table.update_item(
        Key={
            "chatbot_id": chatbot_id,
            "user_id": user_id
        },
        UpdateExpression='SET #vc = #vc + :count',
        ExpressionAttributeNames={
            '#vc': 'source_count',
        },
        ExpressionAttributeValues={
            ':count': count,
        }
    )


def save_widget_config(chatbot_id, heading, subheading, first_message,show_branded_text,
                                        button_color,header_color, widget_color, chatbot_text_color, chatbot_background_color
                                        , user_text_color, user_background_color):
    
    dynamodb = dynamo_connect()
    widget_table = dynamodb.Table("widget")
    widget_id = str(uuid.uuid4())
    widget_table.put_item(
        Item={
            "widget-id":widget_id,
            "chatbot_id":chatbot_id,
            "heading":heading,
            "subheading":subheading,
            "first-message":first_message,
           
            "button-color":button_color,
            "header-color":header_color,
            "widget-color":widget_color,
            
            "show-branded-text":show_branded_text,
            "chatbot-text-color":chatbot_text_color,
            "chatbot-background-color":chatbot_background_color,
            "user-text-color":user_text_color,
            "user-background-color":user_background_color,
            'created-ts':datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S') 
        }
    )        
    return widget_id

def get_widget_config(chatbot_id):
    dynamodb = dynamo_connect()
    widget_table = dynamodb.Table("widget")
    response = widget_table.scan(
        FilterExpression='chatbot_id = :chatbot_id',
        ExpressionAttributeValues={
            ':chatbot_id':chatbot_id
        }
    )
    items = response.get('Items', [])
    if items:
        return items[0]  # Return the first matching widget
    else:
        return None
    
# save default widget config
def save_default_widget_config(chatbot_id,default_widget_config):
    dynamodb = dynamo_connect()
    widget_table = dynamodb.Table("widget")
    widget_id = str(uuid.uuid4())
    created_ts=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S') 
    default_widget_config["widget_id"]=widget_id
    default_widget_config["created_ts"]=created_ts
    default_widget_config["chatbot_id"]=chatbot_id
    widget_table.put_item(
        Item=default_widget_config
    )
