from bs4 import BeautifulSoup
from urllib.request import urlopen
import json
import PyPDF2 , docx
import io,uuid
import boto3
import os ,s3 ,re
import dynamo
import db
import string
import requests
from datetime import datetime,timedelta
import secrets
import smtplib
import re, random
from email.mime.text import MIMEText
from urllib.parse import urlencode
from langchain.chains import ConversationalRetrievalChain
from werkzeug.utils import secure_filename
from langchain.document_loaders import DirectoryLoader
from langchain.text_splitter import CharacterTextSplitter , TokenTextSplitter
from langchain.chains.conversational_retrieval.prompts import CONDENSE_QUESTION_PROMPT
from langchain.vectorstores import Pinecone
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.chains import RetrievalQA
from langchain.llms import OpenAI
from langchain.chat_models import ChatOpenAI
from langchain.document_loaders import TextLoader
import urllib.request
from PyPDF2 import PdfReader
from langchain.memory import ConversationBufferMemory
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.prompts import load_prompt
from constants import *
import tiktoken 

def get_html_of_url(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    page = urllib.request.urlopen(req)
    html = page.read().decode("utf-8")
    soup = BeautifulSoup(html, "html.parser")
    return soup


def get_all_url(url):
    urls=[]
    urls.append(url)
    try:
        soup=get_html_of_url(url)
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and href != '#':
                if href.startswith('/'):
                    s=url+href[1:]
                    if s not in urls:
                        urls.append(s) 

                if href.startswith(url) and href not in urls:
                    urls.append(href)

                if '#' in href:
                    href=href.split('#')[0]
                    s=url+href
                    if s not in urls:
                        urls.append(s)

    except:
        return urls

    return urls


def scrape_url(url):
    response=[]
    if url[-1] != '/':
        url=url+'/'
    sub_urls=get_all_url(url)
    sub_url=[] 
    count=0
    texts = []
    for url in sub_urls:
        soup = get_html_of_url(url)
        page_text = "\n".join([line.strip() for line in soup.get_text().split("\n") if line.strip()])
        text=str(page_text)
        texts.append(text)
        text_bytes = text.encode('utf-8')
        fo = io.BytesIO(text_bytes)
        file_name = str(uuid.uuid4()) + ".txt"
        u = s3.upload_to_s3(file_name, fo)
        response.append({"file_url":u,"count":len(text_bytes)})
        sub_url.append({"url":url,"count":len(text_bytes)})
        count+=len(text_bytes)
    texts = '\n'.join(texts)
    return (sub_url,response,count,texts)


def load_file(file_url, name_space):
    try:
        response = urllib.request.urlretrieve(file_url)
        loader = TextLoader(response[0],encoding='utf-8')
        docs = loader.load()
        text = docs[0].page_content
        text_splitter = TokenTextSplitter(chunk_size=CHUNK_SIZE, chunk_overlap=0)
        texts = text_splitter.split_text(docs[0].page_content)
        api_key = os.getenv("OPENAI_KEY")
        embeddings = OpenAIEmbeddings(openai_api_key=api_key)
        # index_name = "aitools"
        Pinecone.from_texts([d for d in texts], embeddings, index_name=INDEX_NAME, namespace=name_space)
        return len(text)
    except:
        return 0
        




def query_index(query, role, name_space):
    api_key = os.getenv("OPENAI_KEY")
    embeddings = OpenAIEmbeddings(openai_api_key=api_key)
    doc_search = Pinecone.from_existing_index(index_name="aitools", embedding=embeddings, namespace=name_space)
    response=''
    if role=='customer service':
        # print(doc_search.as_retriever())
        memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
        qa = ConversationalRetrievalChain.from_llm(ChatOpenAI(openai_api_key=api_key,temperature=0.0), doc_search.as_retriever(), memory=memory)
        result = qa({"question": query})
        response=result['answer']
    elif role=='question answer':
        llm = ChatOpenAI(streaming=True,openai_api_key=api_key, temperature=0.0)
        qa = RetrievalQA.from_chain_type(llm=llm,
                                    chain_type="stuff",
                                    retriever=doc_search.as_retriever())
        response = qa.run(query)
    else:
        response="Invalid Role"
    return response




def index_file(file, user_id):
    ext = file.filename.split(".")[1]
    if ext == "pdf":
        text = pdf_to_pages(file)

    elif ext=="docx":
        doc = docx.Document(file)
        text = "\n".join([paragraph.text for paragraph in doc.paragraphs])
        print(text)

    else:
        text = read_file(file)
    text_bytes = text.encode('utf-8')
    fo = io.BytesIO(text_bytes)

    new_s=file.filename.lower().replace(" ", "").split('.')
    file_name = str(uuid.uuid4()) + "_" + new_s[0]+'.txt'
    print(file_name)
    url = s3.upload_to_s3(file_name, fo)
    return (url,len(text_bytes),text)

def read_file(file):
    # temp_path = os.getenv("")
    filename = secure_filename(file.filename)
    file.save(os.path.join("/", filename))
    with open("/"+filename) as f:
        file_content = f.read()
    return file_content

def pdf_to_pages(file):
    pages = ""
    reader = PdfReader(file)
    for p in range(0, len(reader.pages)):
        page = reader.pages[p]
        text = page.extract_text()
        pages += text
    return pages


def generate_questions(chatbot_id,text,user_id):
    
    bot_language= "English"
    query=resolve_ques_prompt(text,bot_language)
    api_key = os.getenv("OPENAI_KEY")
    llm = OpenAI(openai_api_key=api_key)
    response=llm(query)
    questions=re.sub(r'\n+', '\n', response).strip().split('\n')
    pattern = r'^\d+\.\s'

    questions = [re.sub(pattern, '', question) for question in questions]
    #print(questions)
    #print(" &&& ")
    new_list=[]
    for i in questions:
        if not i.startswith(('Ques',"Q","Translation:","¿")):
            new_list.append(i)
    new_list = new_list[:3]
    #print(new_list)
    dynamo.save_questions(chatbot_id, new_list, user_id)


def resolve_ques_prompt(text,bot_language):
    template = load_prompt("prompts/genrerate_question.yaml") 
    prompt = template.format(context=text,language=bot_language)
    return prompt



def create_chunks(text):
    char_text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    texts = char_text_splitter.split_text(text)
    return texts

def limit_check(texts):
    messages=[]
    for item in texts: 
        messages.append(item)  
        token_count = get_token_count(messages)
        if token_count >= LIMIT:
            messages.pop()
            break
    return messages

def get_token_count(messages):
    tokens = num_tokens_from_messages(messages)
    return tokens


def num_tokens_from_messages(messages, model="gpt-3.5-turbo-0301"):
    """Returns the number of tokens used by a list of messages."""
    try:
        encoding = tiktoken.encoding_for_model(model)
    except KeyError:
        encoding = tiktoken.get_encoding("cl100k_base")
    if model == "gpt-3.5-turbo-0301":  # note: future models may deviate from this
        num_tokens = 0
        for value in messages:
            num_tokens += len(encoding.encode(value))
        return num_tokens
        
    else:
        raise NotImplementedError(f"""num_tokens_from_messages() is not presently implemented for model {model}""")
def generate_reset_token(length=10, expiry_minutes=1440):
    # Generate a random token of the specified length
    characters = string.ascii_letters + string.digits
    reset_token = ''.join(secrets.choice(characters) for _ in range(length))
    # Calculate the token expiry timestamp
    current_time = datetime.now()
    expiry_time = current_time + timedelta(minutes=expiry_minutes)

    # Encode the expiry timestamp in the token itself
    encoded_token = f"{reset_token}-{expiry_time.timestamp()}"

    # Return the encoded token
    return encoded_token

def generate_reset_url(reset_token):
    base_url = os.getenv('RESET_URL_BASE')
    query_params = {'reset_token': reset_token}
    reset_url = str (base_url) + '?' + urlencode(query_params)
    return reset_url

def send_reset_token_email(email, reset_url):
    subject = "Reset your password for Chatty"
    body=f"Hi there,\
          \n\nPlease follow this link to reset your Chatty password for your {email} account.\
          \n\n{reset_url}\
          \n\nIf you didn’t ask to reset your password, you can ignore this email.\
          \n\nThanks,\
          \n\nYour Chatty team"
    sender = "your_email@example.com"
    recipient = email
    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient

    with smtplib.SMTP("smtp-relay.sendinblue.com", 587) as server:
        server.starttls()
        # server.login("billing@happychat.ai", "qxmhrjU0WAXt6pzk")
        server.login("gunendu87@gmail.com", "td019IDOnkPfmpGU")     
        server.send_message(message)

def index_QA(text):
    text_bytes = text.encode('utf-8')
    fo = io.BytesIO(text_bytes)
    file_name = str(uuid.uuid4())+".txt"
    url = s3.upload_to_s3(file_name, fo)
    page_count=1+len(text_bytes)//CHARACTERS_COUNT
    return (url, page_count)



# scrapping of sitemap urls
def scrape_sitemap_url(sitemap_url):
    response = requests.get(sitemap_url)
    soup = BeautifulSoup(response.text, "html.parser")
    loc_tags = soup.find_all("loc")
    sub_urls = [loc_tag.text for loc_tag in loc_tags]

    file_urls=[];texts=[];page_count=0;sub_url=[];response=[]
    for url in sub_urls:
        text,file_url,character=text_from_url(url)
        file_urls.append(file_url)
        texts.append(text) 
        text_bytes = text.encode('utf-8')
        fo = io.BytesIO(text_bytes)
        file_name = str(uuid.uuid4()) + ".txt"
        u = s3.upload_to_s3(file_name, fo)
        response.append({"file_url":u,"count":len(text_bytes)})
        sub_url.append({"url":url,"count":len(text_bytes)}) 
        page_count+=1+character//CHARACTERS_COUNT
        
    texts = ''.join(texts)
    return (sub_url,response,page_count,texts)

def text_from_url(url):
    soup = get_html_of_url(url)
    page_text = "\n".join([line.strip() for line in soup.get_text().split("\n") if line.strip()])
    text=str(page_text)   
    text_bytes = text.encode('utf-8')
    fo = io.BytesIO(text_bytes)
    file_name = str(uuid.uuid4()) + ".txt"
    file_url = s3.upload_to_s3(file_name, fo)
    character=len(text_bytes)
    return text,file_url,character