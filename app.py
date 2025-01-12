import model
import os

# import flask
from flask import Flask, abort
from flask import json, request
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask import jsonify
from constants import *
import db
from datetime import datetime
import jwt
import dynamo
import logging
import requests
import random
import string
import stripe
import datetime
import base64
from apscheduler.schedulers.background import BackgroundScheduler
from constants import *
import uuid

# set configuration values
class Config:
    SCHEDULER_API_ENABLED = True

app = Flask(__name__, template_folder='template')
stripe.api_key = 'sk_test_51NI8CCIMpXOoP7n4OveVR5AM2laQqAsfCEkg7b4qeKO26y1Caf9kagpZmf2h4VqApeEWIK9edkpYvXS6vwU9v6DM00NOzp6ewx'
bcrypt = Bcrypt(app)
CORS(app)
app.config.from_object(Config())
app.config.from_object('config')
#app.config['CORS_HEADERS'] = 'Content-Type'
default_widget_config=app.config['DEFAULT_WIDGET']

if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)



def update_user_statuses():
    users = dynamo.get_all_user()
    valid_till = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
    for user in users:
        if datetime.datetime.utcnow() >= user['valid_till'] and user['user_status'] == 'Active' and user['is_cancel'] == True:
            dynamo.update_user(user['user-id'], 'no_of_messages', 10)
            dynamo.update_user(user['user-id'], 'no_of_characters', 100)
            dynamo.update_user(user['user-id'], 'no_of_chatbots', 1)
            dynamo.update_user(user['user-id'], 'user_status', "Active")
            dynamo.update_user(user['user-id'], 'is_cancel', False)
        if user['plan_name'] == 'Basic Yearly' and user['user_status'] == 'Active' and datetime.datetime.utcnow() >= user['valid_till']:
            dynamo.update_user(user['user-id'], 'no_of_messages', 5000)
            dynamo.update_user(user['user-id'], 'no_of_characters', 2000000)  # not decided yet
            dynamo.update_user(user['user-id'], 'no_of_chatbots', 10)
            dynamo.update_user(user['user-id'], 'valid_till', valid_till)
            dynamo.update_user(user['user-id'], 'is_cancel', False)
        if user['plan_name'] == 'Pro Yearly' and user['user_status'] == 'Active' and datetime.datetime.utcnow() >= user['valid_till']:
            dynamo.update_user(user['user-id'], 'no_of_messages', -1)
            dynamo.update_user(user['user-id'], 'no_of_characters', 20000000)  # not decided yet
            dynamo.update_user(user['user-id'], 'no_of_chatbots', 10)
            dynamo.update_user(user['user-id'], 'valid_till', valid_till)
            dynamo.update_user(user['user-id'], 'is_cancel', False)
        if user['plan_name'] == 'Enterprise Yearly' and user['user_status'] == 'Active' and datetime.datetime.utcnow() >= user['valid_till']:
            dynamo.update_user(user['user-id'], 'no_of_messages', -1)
            dynamo.update_user(user['user-id'], 'no_of_characters', 200000000)  # not decided yet
            dynamo.update_user(user['user-id'], 'no_of_chatbots', -1)
            dynamo.update_user(user['user-id'], 'valid_till', valid_till)
            dynamo.update_user(user['user-id'], 'is_cancel', False)
    return jsonify({'status': 'success'}), 200


scheduler = BackgroundScheduler()
scheduler.add_job(update_user_statuses, 'interval', minutes=30)
scheduler.start()

def generate_referral_code(length=8):
    characters = string.ascii_letters + string.digits
    referral_code = ''.join(random.choices(characters, k=length))
    return referral_code


@app.route("/chatty/get_user", methods=['GET'])
def get_user():
    email = request.args.get('email')
    users = dynamo.get_user(email)
    if len(users) > 0:
        user = users[0]
        user.pop('password', None)
        return (json.dumps({'user_id': user['user-id'], 'email': user['email'], 'user_name': user['user_name'],
                            'referral_code': user['referral_code'], 'referral_count': user['referral_count'],
                            'is_sso': user['is_sso'], 'email_verified': user['email_verified'],
                            'no_of_referred_chatbots': user['no_of_referred_chatbots'],
                            'no_of_chatbots': user['no_of_chatbots'], 'user_status': user['user_status'],
                            'is_cancel': user['is_cancel'], 'plan_name': user['plan_name'],
                            'no_of_messages': user['no_of_messages'], 'no_of_characters': user['no_of_characters'],
                            'customer_id': user['customer_id'], 'subscription_id': user['subscription_id'], 'hobby': user['hobby']}), 200)
    else:
        return jsonify({'message': 'User not found'}), 404


@app.route("/chatty/signup", methods=['POST'])
def signup():
    data = request.get_json()
    first_name = data['first_name']
    last_name = data['last_name']
    user_name = first_name + " " + last_name
    email = data['email']
    _referral_code = data.get('referral_code')
    is_sso = False
    password = data['password']
    email_verified = False
    referral_code = generate_referral_code()
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    expiration_time = (datetime.datetime.utcnow() + datetime.timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
    users = dynamo.get_user(email)
    if len(users) > 0:
        return json.dumps({'message': 'User already exists with this email'}), 400
    if _referral_code:
        users = dynamo.get_user_by_referral_code(data['referral_code'])
        if len(users) > 0:
            user = users[0]
            updated_count = user['referral_count'] + 1
            dynamo.update_user(user['user-id'], 'referral_count', updated_count)
            if user['referral_count'] == 5:
                dynamo.update_user(user['user-id'], 'no_of_referred_chatbots', 1)
                dynamo.update_user(user['user-id'], 'referral_count', 0)
        else:
            return json.dumps({'message': 'Invalid referral code'}), 400

    user_id = dynamo.save_user(user_name, email, pw_hash, is_sso, referral_code, email_verified)

    # try:
    #     customer = stripe.Customer.create(
    #         email=email,
    #         name=user_name,
    #     )
    #     user_id = dynamo.save_user(user_name, email, pw_hash, customer.id)
    #     return jsonify({
    #         'user_id': user_id,
    #         'email': email,
    #         'user_name': user_name,
    #         'customer_id': customer.id
    #     }), 200
    # except stripe.error.StripeError as e:
    #     return jsonify(error=str(e)), 40

    payload = {
        'username': user_name,
        'user_id': user_id,
        'email': email,
        'exp': expiration_time
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm='HS256')
    verify_url = "http://ec2-54-160-81-7.compute-1.amazonaws.com:3000/verify-email?token=" + token
    sender = os.getenv("FROM_EMAIL")
    recipient = email
    subject = 'Activate Your Account Now!'
    body = 'To verify your email click the following link: ' + verify_url
    data = {
        'From': sender,
        'To': recipient,
        'Subject': subject,
        'TextBody': body
    }
    requests.post(
        'https://api.postmarkapp.com/email',
        headers={'Content-Type': 'application/json', 'X-Postmark-Server-Token': os.getenv("POSTMARK_API_TOKEN")},
        json=data
    )
    return (json.dumps({'user_id': user_id, 'email': email, 'user_name': user_name, 'referral_code': referral_code,
                        'referral_count': 0, 'is_sso': is_sso, 'email_verified': email_verified,
                        'no_of_referred_chatbots': 0, 'no_of_chatbots': 1, 'user_status': 'Active',
                        'is_cancel': False, 'plan_name': None, 'no_of_messages': 500, 'no_of_characters': 10000,
                        'customer_id': None}), 200)


@app.route("/chatty/email_capturing", methods=['POST'])
def email_capturing():
    data = request.get_json()
    email = data['email']
    dynamo.email_capturing(email)


@app.route("/chatty/verify_email", methods=['POST'])
def verify_email():
    data = request.get_json()
    expiration_time = (datetime.datetime.utcnow() + datetime.timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
    #exp_timestamp = int(expiration_time.timestamp())
    token = data['token']
    header, payload, signature = token.split(".")
    decoded_payload = base64.urlsafe_b64decode(payload + "===").decode("utf-8")
    payload_data = json.loads(decoded_payload)
    users = dynamo.get_user(payload_data['email'])
    if len(users) > 0:
        user = users[0]
        dynamo.update_user(user['user-id'], 'email_verified', True)
        payload = {
            'username': user['user_name'],
            'user_id': user['user-id'],
            'email': user['email'],
            'exp': expiration_time
        }
        token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm='HS256')
        return (json.dumps({'user_id': user['user-id'], 'email': user['email'], 'user_name': user['user_name'],
                            'referral_code': user['referral_code'], 'referral_count': user['referral_count'],
                            'is_sso': user['is_sso'], 'email_verified': True, 'access_token': token,
                            'no_of_referred_chatbots': user['no_of_referred_chatbots'],
                            'no_of_chatbots': user['no_of_chatbots'], 'user_status': user['user_status'],
                            'is_cancel': user['is_cancel'], 'plan_name': user['plan_name'],
                            'no_of_messages': user['no_of_messages'], 'no_of_characters': user['no_of_characters'],
                            'customer_id': user['customer_id']}), 200)
    else:
        return json.dumps({'message': 'User not found'}), 400


@app.route("/chatty/forgot_password", methods=['POST'])
def forgot_password():
    data = request.get_json()
    expiration_time = (datetime.datetime.utcnow() + datetime.timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
    email = data['email']
    users = dynamo.get_user(email)
    if len(users) > 0:
        user = users[0]
        if user:
            pass
        else:
            return json.dumps({'message': 'User not found'}), 404
        payload = {
            'username': user['user_name'],
            'user_id': user['user-id'],
            'email': user['email'],
            'exp': expiration_time
        }
        token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm='HS256')
        reset_password_url = "http://ec2-54-160-81-7.compute-1.amazonaws.com:3000/chatty/reset_password?reset_token=" + token
        print("reset_urls",reset_password_url)
        sender = os.getenv("FROM_EMAIL")
        recipient = email
        subject = 'Oops! Forgotten Something?'
        body = 'Click the following link to reset your password: ' + reset_password_url
        data = {
            'From': sender,
            'To': recipient,
            'Subject': subject,
            'TextBody': body
        }
        requests.post(
            'https://api.postmarkapp.com/email',
            headers={'Content-Type': 'application/json', 'X-Postmark-Server-Token': os.getenv("POSTMARK_API_TOKEN")},
            json=data
        )


# @app.route("/chatty/reset_password", methods=['POST'])
# def reset_password():
#     data = request.get_json()
#     token = data['token']
#     password = data['password']
#     decoded_token = jwt.decode(token, os.getenv("JWT_SECRET_KEY"), algorithms=['HS256'])
#     user = dynamo.get_user(decoded_token['email'])
#     if user:
#         pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
#         dynamo.update_user(user['user-id'], 'password', pw_hash)
#         sender = os.getenv("FROM_EMAIL")
#         recipient = decoded_token['email']
#         subject = 'Password Reset Successfully'
#         body = 'Your password for chatty.to has been reset successfully'
#         data = {
#             'From': sender,
#             'To': recipient,
#             'Subject': subject,
#             'TextBody': body
#         }
#         requests.post(
#             'https://api.postmarkapp.com/email',
#             headers={'Content-Type': 'application/json', 'X-Postmark-Server-Token': os.getenv("POSTMARK_API_TOKEN")},
#             json=data
#         )
#     else:
#         return json.dumps({'message': 'User not found'}), 404


@app.route("/chatty/create_google_user", methods=['POST'])
def create_google_user():
    data = request.get_json()
    user_name = data['user_name']
    email = data['email']
    is_sso = True
    pw_hash = None
    _referral_code = data.get('referral_code')
    referral_code = generate_referral_code()
    email_verified = True
    expiration_time = (datetime.datetime.utcnow() + datetime.timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
    users = dynamo.get_user(email)
    if len(users) > 0:
        user = users[0]
        if 'is_sso' in user and user['is_sso']:
            pass
        else:
            return json.dumps({'message': 'Invalid credentials'}), 400
        payload = {
            'username': user['user_name'],
            'user_id': user['user-id'],
            'email': email,
            'exp': expiration_time
        }
        token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm='HS256')
        return (json.dumps({'user_id': user['user-id'], 'email': user['email'], 'user_name': user['user_name'],
                            'referral_code': user['referral_code'], 'referral_count': user['referral_count'],
                            'is_sso': user['is_sso'], 'email_verified': user['email_verified'],
                            'customer_id': user['customer_id'], 'access_token': token,
                            'no_of_referred_chatbots': user['no_of_referred_chatbots'],
                            'no_of_chatbots': user['no_of_chatbots'],
                            'user_status': user['user_status'], 'is_cancel': user['is_cancel'],
                            'plan_name': user['plan_name'],
                            'no_of_messages': user['no_of_messages'], 'no_of_characters': user['no_of_characters']}),
                200)

    if _referral_code:
        users = dynamo.get_user_by_referral_code(data['referral_code'])
        if len(users) > 0:
            user = users[0]
            updated_count = user['referral_count'] + 1
            dynamo.update_user(user['user-id'], 'referral_count', updated_count)
            if user['referral_count'] == 5:
                dynamo.update_user(user['user-id'], 'no_of_referred_chatbots', 1)
                dynamo.update_user(user['user-id'], 'referral_count', 0)
        else:
            return json.dumps({'message': 'Invalid referral code'}), 400

    sender = os.getenv("FROM_EMAIL")
    recipient = email
    subject = 'Sign Up Successfully'
    body = 'Sign Up'
    data = {
        'From': sender,
        'To': recipient,
        'Subject': subject,
        'TextBody': body
    }
    requests.post(
        'https://api.postmarkapp.com/email',
        headers={'Content-Type': 'application/json', 'X-Postmark-Server-Token': os.getenv("POSTMARK_API_TOKEN")},
        json=data
    )

    user_id = dynamo.save_user(user_name, email, pw_hash, is_sso, referral_code, email_verified)
    payload = {
        'username': user_name,
        'user_id': user_id,
        'email': email,
        'exp': expiration_time
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm='HS256')
    return (json.dumps({'user_id': user_id, 'email': email, 'user_name': user_name, 'referral_code': referral_code,
                        'referral_count': 0, 'is_sso': is_sso, 'email_verified': email_verified,
                        'customer_id': None, 'access_token': token, 'no_of_referred_chatbots': 0,
                        'no_of_chatbots': 1, 'user_status': 'Active', 'is_cancel': False, 'plan_name': None,
                        'no_of_messages': 500, 'no_of_characters': 10000}), 200)


@app.route("/chatty/login", methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    users = dynamo.get_user(email)
    if len(users) > 0:
        user = users[0]
        if user and 'is_sso' in user and user['is_sso'] != True:
            pass
        else:
            return json.dumps({'message': 'Invalid credentials'}), 400
        pw_hash = user['password']
        is_valid = bcrypt.check_password_hash(pw_hash, password)
        if is_valid:
            expiration_time = (datetime.datetime.utcnow() + datetime.timedelta(minutes=30)).strftime(
                '%Y-%m-%d %H:%M:%S')
            payload = {
                'username': user['user_name'],
                'user_id': user['user-id'],
                'email': email,
                'exp': expiration_time
            }
            token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm='HS256')
            return (json.dumps({'user_id': user['user-id'], 'email': user['email'], 'user_name': user['user_name'],
                                'referral_code': user['referral_code'], 'referral_count': user['referral_count'],
                                'is_sso': user['is_sso'], 'email_verified': user['email_verified'],
                                'customer_id': user['customer_id'], 'access_token': token,
                                'no_of_referred_chatbots': user['no_of_referred_chatbots'],
                                'no_of_chatbots': user['no_of_chatbots'],
                                'user_status': user['user_status'], 'is_cancel': user['is_cancel'],
                                'plan_name': user['plan_name'],
                                'no_of_messages': user['no_of_messages'],
                                'no_of_characters': user['no_of_characters']}), 200)
        else:
            return json.dumps({'message': 'Invalid password'}), 400

    return json.dumps({'message': 'Invalid password'}), 400


@app.route("/chatty/scrape", methods=["POST"])
def scrape():
    data = request.get_json()
    user_id = data.get('user_id', "")
    website_url = data.get('website', "")
    source_type=data['source_type']
    
    if source_type==SOURCE_URL:
        sub_urls, file_url, count, text = model.scrape_url(website_url)
        chatbot_id = dynamo.save_url(user_id, website_url, file_url, count)

    elif source_type==SOURCE_SITEMAP:
        sub_urls, file_url, count, text= model.scrape_sitemap_url(website_url)
        chatbot_id = dynamo.save_url(user_id, website_url, file_url, count)
        
    texts=model.create_chunks(text)
    response=model.limit_check(texts)   
    query="".join(response)        
    model.generate_questions(chatbot_id,query,user_id)
    widget_id=dynamo.save_default_widget_config(chatbot_id,default_widget_config)
    return json.dumps({"chatbot_id": chatbot_id, "sub_urls": sub_urls, "file_url": file_url}), 200


@app.route("/chatty/embed", methods=["POST"])
def embed():
    data = request.get_json()
    chatbot_id = data.get("chatbot_id", "")
    chatbot_name = data.get("chatbot_name", "")
    file_url = data.get("file_url", [])
    user_email = data["user_email"]
    user_id = data["user_id"]
    
    name_space = chatbot_name + "_" + chatbot_id
    total_len= 0
    for url in file_url:
        text_len = model.load_file(url, name_space)
        total_len = total_len + text_len
    dynamo.update_chatbot_name(chatbot_id, chatbot_name,total_len)
    chatbots = dynamo.chatbot_meta(chatbot_id)
    if len(chatbots) > 0:
        chatbot = chatbots[0]
        users = dynamo.get_user(user_email)
        if len(users) > 0:
            user = users[0]
            if user['no_of_characters'] > 0:
                dynamo.update_user(user_id, 'no_of_characters', user['no_of_characters'] - chatbot['character_count'])
            if user['no_of_chatbots'] > 0:
                dynamo.update_user(user_id, 'no_of_chatbots', user['no_of_chatbots'] - 1)   
    return json.dumps({"status": "success"}), 200


@app.route("/chatty/get_characters_count", methods=["GET"])
def get_characters_count():
    data = request.get_json()
    chatbot_id = data["chatbot_id"]
    chatbots = dynamo.chatbot_meta(chatbot_id)
    if len(chatbots) > 0:
        chatbot = chatbots[0]
        return json.dumps({"character_count": chatbot['character_count']}), 200
    else:
        return json.dumps({'message': 'Chatbot not found'}), 404


@app.route("/chatty/ask_question", methods=['POST'])
def ask_question():
    data = request.get_json()
    chatbot_id = data.get("chatbot_id", "")
    chatbot_name = data.get("chatbot_name", "")
    query = data.get("query", "")
    role = data.get("role", "")
    user_email = data.get("user_email") 
    
    name_space = chatbot_name + "_" + chatbot_id
    response = model.query_index(query, role, name_space)
    print(type(response))
    dynamo.update_chatbot_role(chatbot_id, role)
    users = dynamo.get_user(user_email)
    if len(users) > 0:
        user = users[0]
        if user['no_of_messages'] != -1:
            updated_messages = user['no_of_messages'] - 1
            dynamo.update_user(user['user-id'], 'no_of_messages', updated_messages)
            
    dynamo.save_chat_history(chatbot_id, chatbot_name, user_email, query, response)
    return json.dumps({"message": response}), 200




@app.route('/chatty/upload_file', methods=['POST'])
def upload_file():
    file = request.files['file']
    data = dict(request.form)
    user_id = data.get('user_id')
    response = model.index_file(file, user_id)
    (file_url, count,text) = response
    chatbot_id = dynamo.save_url(user_id, file.filename, file_url, count)
    
    texts=model.create_chunks(text)
    response=model.limit_check(texts)   
    query="".join(response)        
    model.generate_questions(chatbot_id,query,user_id)
    widget_id=dynamo.save_default_widget_config(chatbot_id,default_widget_config)
    return json.dumps({"url": file_url, "chatbot_id": chatbot_id, "count": count}), 200

@app.route('/chatty/chatbot/questions' ,methods=['GET'])
def get_questions(): 
    request_args = request.args
    if request_args and 'chatbot_id' in request_args:
        chatbot_id = request_args['chatbot_id']
    response=dynamo.get_questions(chatbot_id)
    if response:
        return (json.dumps({"quesions":response}),200)
    else:
        return (json.dumps({'message':"Invalid bot Id"}),404)
    

@app.route('/chatty/chatbot_history', methods=['POST'])
def chatbot_history():
    data = request.get_json()
    user_id = data.get('user_id', "")
    
    response = dynamo.get_chatbot_history(user_id)
    if len(response) > 0:
        res = []
        for item in response:
            chatbot_name = item.get('chatbot_name', "")
            chatbot_id = item['chatbot_id']
            created_ts = item['created_ts']
            website_url = item['website_url']
            role = item.get('role', "")
            chat_history=item.get('history',[])
            quesition_count=item.get('question_count',0)
            res.append({'chatbot_id': chatbot_id, "chatbot_name": chatbot_name, "website_url": website_url,
                        "created_at": created_ts, "role": role,'chat_history':chat_history,'quesition_count':quesition_count})
        return json.dumps({"history": res})
        
    else:
        return json.dumps({'message': "Invalid User Id"})


@app.route('/chatty/get_all_users', methods=['POST'])
def get_all_users():
    response = dynamo.get_all_user()
    if len(response) > 0:
        users = []
        for item in response:
            user_id = item['user-id']
            user_name = item['user_name']
            email = item['email']
            created_ts = item.get('created_ts', "")
            users.append({'user_id': user_id, 'user_name': user_name, 'email': email, 'created_ts': created_ts})
        return json.dumps({"Users": users})
    else:
        return json.dumps({'message': "Table is Empty"})


@app.route('/chatty/get_chatbot_meta', methods=['GET'])
def get_chatbot_meta():
    response = dynamo.get_all_data()

    if len(response) > 0:
        chatbot_meta_counts = []
        user_ids = []
        for item in response:
            user_id = item['user_id']
            if user_id not in user_ids:
                user_ids.append(user_id)

        for id in user_ids:
            resp = dynamo.get_chatbot_history(id)
            total_chatbot = len(resp)
            total_character = 0
            for item in resp:
                count = item.get('character_count', 0)
                total_character += count
            chatbot_meta_counts.append({"user_id": id, "total_chatbot": total_chatbot, "uploaded_doc": total_chatbot,
                                        "total_character": total_character})
        return json.dumps({"chatbot_meta_count": chatbot_meta_counts})
    else:
        return json.dumps({'message': "Table is Empty"})


@app.route('/stripe_webhook', methods=['POST'])
def webhook():
    payload = request.data
    event = stripe.Webhook.construct_event(
        payload, request.headers.get('stripe-signature'), 'whsec_R7PmCOX2nJlVczwHyMZe8fE7ibsXdafK'
    )
    valid_till = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
    if event['type'] == 'invoice.payment_succeeded':
        customer_id = event['data']['object']['customer']
        subscription_id = event['data']['object']['subscription']
        subscription = stripe.Subscription.retrieve(subscription_id)
        price_id = subscription.plan.id
        dynamo.update_user_by_customer_id(customer_id, 'subscription_id', subscription_id)
        dynamo.update_user_by_customer_id(customer_id, 'user_status', "Active")
        if price_id == 'price_1NJvHuIMpXOoP7n4Cm6Pqute':
            dynamo.update_user_by_customer_id(customer_id, 'no_of_messages', 5000)
            dynamo.update_user_by_customer_id(customer_id, 'no_of_characters', 2000000)  # not decided yet
            dynamo.update_user_by_customer_id(customer_id, 'no_of_chatbots', 5)
            dynamo.update_user_by_customer_id(customer_id, 'plan_name', 'Basic Monthly')
            dynamo.update_user_by_customer_id(customer_id, 'valid_till', valid_till)
            dynamo.update_user_by_customer_id(customer_id, 'is_cancel', False)
        elif price_id == 'price_1NJvIUIMpXOoP7n4IIUwrg7s':
            dynamo.update_user_by_customer_id(customer_id, 'no_of_messages', 5000)
            dynamo.update_user_by_customer_id(customer_id, 'no_of_characters', 2000000)  # not decided yet
            dynamo.update_user_by_customer_id(customer_id, 'no_of_chatbots', 10)
            dynamo.update_user_by_customer_id(customer_id, 'plan_name', 'Basic Yearly')
            dynamo.update_user_by_customer_id(customer_id, 'valid_till', valid_till)
            dynamo.update_user_by_customer_id(customer_id, 'is_cancel', False)
        elif price_id == 'price_1NJvItIMpXOoP7n4quNzRrP8':
            dynamo.update_user_by_customer_id(customer_id, 'no_of_messages', -1)
            dynamo.update_user_by_customer_id(customer_id, 'no_of_characters', 20000000)  # not decided yet
            dynamo.update_user_by_customer_id(customer_id, 'no_of_chatbots', 10)
            dynamo.update_user_by_customer_id(customer_id, 'plan_name', 'Pro Monthly')
            dynamo.update_user_by_customer_id(customer_id, 'valid_till', valid_till)
            dynamo.update_user_by_customer_id(customer_id, 'is_cancel', False)
        elif price_id == 'price_1NJvJKIMpXOoP7n40BZsrXqL':
            dynamo.update_user_by_customer_id(customer_id, 'no_of_messages', -1)
            dynamo.update_user_by_customer_id(customer_id, 'no_of_characters', 20000000)  # not decided yet
            dynamo.update_user_by_customer_id(customer_id, 'no_of_chatbots', 10)
            dynamo.update_user_by_customer_id(customer_id, 'plan_name', 'Pro Yearly')
            dynamo.update_user_by_customer_id(customer_id, 'valid_till', valid_till)
            dynamo.update_user_by_customer_id(customer_id, 'is_cancel', False)
        elif price_id == 'price_1NJvJqIMpXOoP7n465UmXh5W':
            dynamo.update_user_by_customer_id(customer_id, 'no_of_messages', -1)
            dynamo.update_user_by_customer_id(customer_id, 'no_of_characters', 200000000)  # not decided yet
            dynamo.update_user_by_customer_id(customer_id, 'no_of_chatbots', -1)
            dynamo.update_user_by_customer_id(customer_id, 'plan_name', 'Enterprise Monthly')
            dynamo.update_user_by_customer_id(customer_id, 'valid_till', valid_till)
            dynamo.update_user_by_customer_id(customer_id, 'is_cancel', False)
        elif price_id == 'price_1NJvKeIMpXOoP7n4eDwmlZUf':
            dynamo.update_user_by_customer_id(customer_id, 'no_of_messages', -1)
            dynamo.update_user_by_customer_id(customer_id, 'no_of_characters', 200000000)  # not decided yet
            dynamo.update_user_by_customer_id(customer_id, 'no_of_chatbots', -1)
            dynamo.update_user_by_customer_id(customer_id, 'plan_name', 'Enterprise Yearly')
            dynamo.update_user_by_customer_id(customer_id, 'valid_till', valid_till)
            dynamo.update_user_by_customer_id(customer_id, 'is_cancel', False)
    elif event['type'] == 'invoice.payment_failed':
        customer_id = event['data']['object']['customer']
        dynamo.update_user_by_customer_id(customer_id, 'no_of_messages', 0)
        dynamo.update_user_by_customer_id(customer_id, 'no_of_characters', 0)
        dynamo.update_user_by_customer_id(customer_id, 'no_of_chatbots', 0)
        dynamo.update_user_by_customer_id(customer_id, 'user_status', "Active")
        dynamo.update_user_by_customer_id(customer_id, 'plan_name', None)
    elif event['type'] == 'customer.subscription.updated':
        customer_id = event['data']['object']['customer']
        subscription_id = event['data']['object']['subscription']
        subscription = stripe.Subscription.retrieve(subscription_id)
        payment_status = event['data']['object']['status']
        price_id = subscription.plan.id
        if payment_status == 'active':
            if price_id == 'price_1NJvHuIMpXOoP7n4Cm6Pqute':
                dynamo.update_user_by_customer_id(customer_id, 'no_of_messages', 5000)
                dynamo.update_user_by_customer_id(customer_id, 'no_of_characters', 2000000)  # not decided yet
                dynamo.update_user_by_customer_id(customer_id, 'no_of_chatbots', 5)
                dynamo.update_user_by_customer_id(customer_id, 'valid_till', valid_till)
                dynamo.update_user_by_customer_id(customer_id, 'is_cancel', False)
            elif price_id == 'price_1NJvItIMpXOoP7n4quNzRrP8':
                dynamo.update_user_by_customer_id(customer_id, 'no_of_messages', -1)
                dynamo.update_user_by_customer_id(customer_id, 'no_of_characters', 20000000)  # not decided yet
                dynamo.update_user_by_customer_id(customer_id, 'no_of_chatbots', 10)
                dynamo.update_user_by_customer_id(customer_id, 'valid_till', valid_till)
                dynamo.update_user_by_customer_id(customer_id, 'is_cancel', False)
            elif price_id == 'price_1NJvJqIMpXOoP7n465UmXh5W':
                dynamo.update_user_by_customer_id(customer_id, 'no_of_messages', -1)
                dynamo.update_user_by_customer_id(customer_id, 'no_of_characters', 200000000)  # not decided yet
                dynamo.update_user_by_customer_id(customer_id, 'no_of_chatbots', -1)
                dynamo.update_user_by_customer_id(customer_id, 'valid_till', valid_till)
                dynamo.update_user_by_customer_id(customer_id, 'is_cancel', False)
    return jsonify({'status': 'success'}), 200


@app.route('/create_subscription', methods=['POST'])
def create_subscription():
    data = request.get_json()
    plan_id = data['plan_id']
    payment_method = data['payment_method']
    email = data['email']
    customer = stripe.Customer.create(
        email=email,
        payment_method=payment_method,
        invoice_settings={
            'default_payment_method': payment_method
        }
    )
    dynamo.update_user(data['user_id'], 'customer_id', customer.id)

    subscription = stripe.Subscription.create(
        customer=customer.id,
        items=[
            {'price': plan_id},
        ],
    )

    return jsonify({'subscription': subscription}), 200


@app.route('/cancel_subscription', methods=['POST'])
def cancel_subscription():
    subscription_id = request.json['subscription_id']
    customer_id = request.json['customer_id']
    subscription = stripe.Subscription.retrieve(subscription_id)
    subscription.cancel_at_period_end = True
    subscription.save()
    dynamo.update_user_by_customer_id(customer_id, 'is_cancel', True)
    return jsonify({'status': 'success', 'message': 'Subscription(s) canceled.'}), 200


@app.route('/renew_subscription', methods=['POST'])
def renew_subscription():
    subscription_id = request.json['subscription_id']
    customer_id = request.json['customer_id']
    subscription = stripe.Subscription.retrieve(subscription_id)
    subscription.cancel_at_period_end = False
    subscription.save()
    dynamo.update_user_by_customer_id(customer_id, 'is_cancel', False)
    return jsonify({'status': 'success', 'message': 'Subscription renewed.'}), 200


@app.route('/create_hobby_subscription', methods=['POST'])
def create_hobby_subscription():
    data = request.get_json()
    payment_method = data['payment_method']
    email = data['email']
    customer = stripe.Customer.create(
        email=email,
        payment_method=payment_method,
        invoice_settings={
            'default_payment_method': payment_method
        }
    )
    payment_intent = stripe.PaymentIntent.create(
        amount=100,
        currency='usd',
        customer=customer.id,
        payment_method=payment_method,
        description='Hobby Deal',
        confirm=True
    )
    valid_till = (datetime.datetime.utcnow() + datetime.timedelta(days=3)).strftime('%Y-%m-%d %H:%M:%S')
    dynamo.update_user(data['user_id'], 'no_of_messages', 500)
    dynamo.update_user(data['user_id'], 'no_of_characters', 20000)  # not decided yet
    dynamo.update_user(data['user_id'], 'no_of_chatbots', 1)
    dynamo.update_user(data['user_id'], 'plan_name', 'Hobby')
    dynamo.update_user(data['user_id'], 'user_status', 'Active')
    dynamo.update_user(data['user_id'], 'valid_till', valid_till)
    dynamo.update_user(data['user_id'], 'customer_id', customer.id)
    dynamo.update_user(data['user_id'], 'hobby', True)
    return payment_intent




@app.route('/', methods=['GET'])
def test():
    return 'working'

@app.route("/chatty/forget_password", methods=['POST'])
def forget_password():
    email = request.get_json().get('email')
    users = dynamo.get_user(email)
    
    if users:
        reset_token = model.generate_reset_token()
        reset_url = model.generate_reset_url(reset_token)
        user_id=dynamo.get_user_id(email)
        dynamo.store_reset_token(user_id, reset_token)
        
        model.send_reset_token_email(email, reset_url)
        
        return json.dumps({'message': 'Password reset link has been sent to your email address'}), 200
    else:
        return json.dumps({'message': 'Invalid email ID'}), 400


   
@app.route("/chatty/reset_password", methods=['POST'])
def reset_password():
    data = request.get_json()
    password = data['password']
    current_password=password
    email=data.get('email',"")
    reset_token=data.get('reset_token',"")
    if reset_token:
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        # Verify the reset token and update the user's password
        user_id = dynamo.verify_reset_token(reset_token)
        if user_id:
            dynamo.update_password(user_id, pw_hash)
            return json.dumps({'message': 'Password reset successfully'}), 200
        else:
            return json.dumps({'message': 'Either the reset token has expired or it is invalid'}), 400
    
    elif current_password:
        # Reset password using current password
        if not password:
            return json.dumps({'message': 'New password is required'}), 400

        # Retrieve the user's current password hash from the database
        user_id=dynamo.get_user_id(email)
        users = dynamo.get_user(email)
        user = users[0]
        pw_hash = user['password']
        is_valid = bcrypt.check_password_hash(pw_hash, current_password)
        
        # Verify the current password
        if is_valid:
            # Update the user's password with the new password
            pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            dynamo.update_password(user_id, pw_hash)
            return (json.dumps({'message': 'Password reset successfully'}), 400)
            
        else:
            return (json.dumps({'message': 'Invalid password'}), 400)
    else:
        return (json.dumps({'message': 'Some error occured'}), 400)
    
@app.route("/chatty/chatbot/sources/QA", methods=['POST'])
# @token_required
def add_QA_source():
    data = request.get_json()
    user_id = data.get('user_id', "")
    qa = data.get('QA', "")
    text=""

    for item in qa:
        question = item['question']
        answer = item['answer']
        text = text + question + "\n" + answer + "\n" 
    (url, page_count) = model.index_QA(text)    
    chatbot_id = dynamo.save_url(user_id, "QA",url,page_count)
    texts=model.create_chunks(text)
    response=model.limit_check(texts)
    query="".join(response)
    model.generate_questions(chatbot_id,query,user_id)
    widget_id=dynamo.save_default_widget_config(chatbot_id,default_widget_config)
    return json.dumps({"chatbot_id": chatbot_id,"file_url": url}), 200

@app.route("/chatty/widget",methods=['POST'])
def save_widget():
    data=request.get_json()
    chatbot_id=data['chatbot_id']
    heading=data['heading']
    subheading=data['subheading']
    first_message=data['first_message']
    button_color=data['button_color']
    header_color=data['header_color']
    widget_color=data['widget_color']
    show_branded_text=data['show_branded_text']  
    chatbot_text_color=data['chatbot_text_color']
    chatbot_background_color=data['chatbot_background_color']
    user_text_color=data['user_text_color']
    user_background_color=data['user_background_color']
    widget_id=dynamo.save_widget_config(chatbot_id, heading, subheading, first_message,show_branded_text,
                                        button_color, header_color, widget_color,chatbot_text_color, chatbot_background_color
                                        , user_text_color, user_background_color)
    
    return json.dumps({'widget_id': widget_id}), 200 

@app.route("/chatty/widget", methods=['GET'])
def get_widget():
    request_args = request.args
    if request_args and 'chatbot_id' in request_args:
       chatbot_id = request_args['chatbot_id']
    widget = dynamo.get_widget_config(chatbot_id)
    if widget is not None:
        return json.dumps({'widget': widget}), 200 
    else:
        return "Widget not found", 404



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
