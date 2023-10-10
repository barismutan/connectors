import openai
from pycti import OpenCTIConnectorHelper
from datetime import datetime

class GptClient:
    def prompt(helper : OpenCTIConnectorHelper, blog : str, apikey : str, model : str, temperature : float, prompt_version : str) -> str:
        return '''
{
    "Title": "Kegtap and Singlemalt: APT28 Uses Vintage Malware to Attack Governments and Energy Sector",
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
        }
    ],
    "Tools": [
        "certutil",
        "BITSAdmin"
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
            "value": "b2a0f0e1c2b2f1e1d2c3b4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5"
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
}
''' #THIS IS A TEST REMOVE THIS LATER
        openai.api_key = apikey
        prompt_dir = f"gpt_enrichment/prompts/{prompt_version}/"
        system_prompt = open(prompt_dir + "system_prompt.txt", "r").read()
        user_prompt = open(prompt_dir + "user_prompt.txt", "r").read()
        helper.log_info(f"Querying the LLM @ time {datetime.now()}")
        response = openai.ChatCompletion.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt + blog},
            ],
            temperature=float(temperature),
            timeout=30
        )

        helper.log_info(f"System prompt:{system_prompt}")
        helper.log_info(f"User prompt:{user_prompt}")
        helper.log_info(f"Response from GPT-engine: {response}")


        return response["choices"][0]["message"]["content"]