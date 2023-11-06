import openai
from pycti import OpenCTIConnectorHelper
from datetime import datetime
import boto3
import time
import requests
from requests_auth_aws_sigv4 import AWSSigV4
import json
import random

class GptClient:
    def __init__(self, api_getaway, output_queue):
        self.sqs_client = boto3.client('sqs', region_name='us-east-1')
        self.api_getaway = api_getaway
        self.output_queue = output_queue
        return
    

    def consume_queue(self,expected_report_id,receive_wait_time=10,total_wait_time=100):
        time_elapsed=receive_wait_time  
        
        response = self.sqs_client.receive_message(
        QueueUrl=self.output_queue,
        MaxNumberOfMessages=1,
        VisibilityTimeout=60,
        WaitTimeSeconds=receive_wait_time
    )
        while time_elapsed<total_wait_time:
            print("Response from queue")
            print(json.dumps(response,indent=4))
            if response.get('Messages') != None:
                print("Received message:")
                print(json.dumps(response,indent=4))
                #delete message
                self.sqs_client.delete_message(
                    QueueUrl=self.output_queue,
                    ReceiptHandle=response['Messages'][0]['ReceiptHandle']
                )
                #check if the report id matches
                message_body=json.loads(response['Messages'][0]['Body'])
                if message_body['report_id'] != expected_report_id:
                    return {"MISMATCH":message_body['report_id']}
                else:
                    return message_body
            else:
                #wait for 5 seconds
                print("Received no messages. Sleeping for 5 seconds before retrying. Total time elapsed: {} seconds".format(time_elapsed))
                print("Response: {}".format(str(response)))
                time.sleep(5)
                time_elapsed+= 5+receive_wait_time #since we are waiting receive_wait_time as well.
                response = self.sqs_client.receive_message(
                    QueueUrl=self.output_queue,
                    MaxNumberOfMessages=1,
                    VisibilityTimeout=60,
                    WaitTimeSeconds=receive_wait_time
                )
        
        return {"TIMEOUT":"TIMEOUT"}
    
    
    def clear_queue(self):
                # response = sqs_client.purge_queue(
        #     QueueUrl=url
        # )
        #NOTE: The reason this doesn't work is because identity-based policies are not allowed to perform this operation (purge queue).
        i=0
        response = self.sqs_client.receive_message(
            QueueUrl=self.output_queue,
            MaxNumberOfMessages=10,
            VisibilityTimeout=60,
            WaitTimeSeconds=0,
        )

        for message in response.get('Messages',[]):
            # print("Deleting message")
            self.sqs_client.delete_message(
                QueueUrl=self.output_queue,
                ReceiptHandle=message['ReceiptHandle']
            )
        
        

        return response
    
    def make_request(self,helper:OpenCTIConnectorHelper,report_id, report_content,custom_prompt=None):
        full_url = self.api_getaway.format(report_id)
        print("Making request to {}".format(full_url))
        headers = {"Content-Type": "application/json; charset=utf-8"}

        # Through REST Requests
        aws_auth = AWSSigV4('execute-api',
                            aws_access_key_id="XXXXXXXX",
                            aws_secret_access_key="XXXXXXXX",
                            aws_session_token="XXXXXXXX",
                            region="us-east-1",
                            # service="apigateway"
                            )
        if custom_prompt != None:
            payload={
                "report_content": report_content,
                "prompt_templates": custom_prompt
            }
            pass
        else:
            payload = {'report_content': report_content}

        r = requests.request('POST',
                                full_url,
                                data=json.dumps(payload),
                                headers=headers,
                                auth=aws_auth)
        
        # print("Response from getaway:")
        # print("Status code: ", r.status_code)
        # print("Body:",r.text)
        #TODO: comment below later
        helper.log_debug("Response from getaway:")
        helper.log_debug("Status code: {}".format(r.status_code))
        helper.log_debug("Body: {}".format(r.text))
        return r
    
    def prompt(self,helper:OpenCTIConnectorHelper,report_id,report_content,custom_prompt=None,test_mode=True):
        if test_mode:
            return \
            json.dumps({
  "Title": "Kegtap and Singlemalt: APT28 Uses Vintage Malware to Attack Governments and Energy Sector",
  "Victim Organization": "N/A",
  "Victim Country": [
    "United States",
    "Canada"
  ],
  "Victim Region": [
    "North America"
  ],
  "Sectors": [
    "Government",
    "Energy"
  ],
  "Threat Actors": [
    {
      "name": "APT28",
      "aliases": [
        "IRON TWILIGHT",
        "Fancy Bear",
        "Pawn Storm",
        "Sofacy Group",
        "Sednit",
        "STRONTIUM",
        "Tsar Team",
        "TG-4127"
      ]
    },
    {
      "name": "Lazarus",
      "aliases": [
        "Hidden Cobra",
        "Guardians of Peace"
      ]
    },
    {
      "name": "Deneme_{}".format(random.randint(0,15000)),
      "aliases": [
        "N/A"
      ]
    }
  ],
  "Actor Motivation": [
    "Cyber Espionage",
    "Financial Gain"
  ],
  "Malware": [
    {
      "name": "Kegtap",
      "types": [
        "backdoor",
        "downloader"
      ]
    },
    {
      "name": "Singlemalt",
      "types": [
        "downloader"
      ]
    },
    {
      "name": "BPFDoor",
      "types": [
        "N/A"
      ]
    },
    {
        "name": "Deneme_{}".format(random.randint(0,15000)),
        "types": [
            
        ]
    }
  ],
  "Tools": [
    "certutil",
    "BITSAdmin",
    "N/A",
    "PowerShell"
  ],
  "Targeted Software": [
    {
      "name": "Microsoft Windows",
      "versions": [
        "Windows10",
        "Windows Server 2017"
      ]
    },
    {
      "name": "MySQL",
      "versions": [
        "v3.5.2",
        "v3.5.3"
      ]
    },
    {
      "name": "OpenVPN",
      "versions": []
    }
  ],
  "CVE": [
    "CVE-2017-11882",
    "CVE-2018-0802"
  ],
  "TTP": [
    {
      "name": "User Execution",
      "id": "T1204"
    },
    {
      "name": "Scripting",
      "id": "T1064"
    }
  ],
  "IoC": [
    {
      "type": "file:hashes.'SHA-256'",
      "value": "N/A"
    },
    {
      "type": "file:hashes.'SHA-1'",
      "value": "a22cce4b39f389ee27accf5895383002cebf46b8"
    },
    {
      "type": "file:hashes.MD5",
      "value": "4c96f960ccc17c17bb8d1dc69488eb96"
    },
    {
      "type": "url",
      "value": "https://anakin.sky/walker/s.php"
    },
    {
      "type": "domain",
      "value": "anakin.sky"
    },
    {
      "type": "ipv4-addr",
      "value": "112.325.13.37"
    }
  ]
})
        #clear the queue

        self.clear_queue()

        print("Sleeping for 10 seconds before making request")


        time.sleep(10)

        #make request
        # report_content="This is a test report."#NOTE:TEST
        #----TEST----
        #generate a random report_id between 0-15000
        # report_id=str(random.randint(0,15000))
        #----TEST----
        api_response=self.make_request(helper,report_id,report_content,custom_prompt)
        if api_response.status_code !=200:
            print("Request failed with status code: {}".format(api_response.status_code))
            return None
        else:
            print("Request succeeded with status code: {}".format(api_response.status_code))
        
        #consume queue

        response=self.consume_queue(report_id) #NOTE:TEST
        
        if "MISMATCH" in response.keys():
            helper.log_error("Report id returned from queue ({}) does not match the expected report id ({})".format(response["MISMATCH"],report_id))
            return None
        elif "TIMEOUT" in response.keys():
            helper.log_error("Queue consume timed out")
            return None
        
        print ("Response from queue:")
        print(json.dumps(response,indent=4))
        return json.dumps(response['fields'])
        

        



