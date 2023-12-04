import unittest

from src.gpt_enrichment.pydantic_models import *

class TestLLMResponseModel(unittest.TestCase):
    def test_llm_response_model(self):
        data = {
            "title": "title",
            "victim_organization":"Walmart",
            "victim_countries": ["United States"],
            "victim_industries": ["Retail"],
            "victim_regions": ["North America"],
            "intrusion_sets": ["Lazarus Group", "APT28"],
            "malware": [
                {
                "name": "AppleJeus",
                "type": "keylogger"
                },
                {
                "name": "Agent Tesla",
                "type": "rat"
                }],
            
            "tools": [
                "certutil",
                "BITSAdmin",
                "N/A",
                "PowerShell"
            ],
            "attack_patterns": [{
                "name": "name",
                "id": "T0001"
            }
            ],
            "vulnerabilities": [
                "CVE-2021-0001"
            ],
            "indicators": [{
                "type": "file:hashes.MD5",
                "value": "0123456789abcdef0123456789abcdef"
            }]
        }
        llm_response_model = LLMResponseModel(**data)
        self.assertEqual(llm_response_model.title, "title")
        self.assertEqual(llm_response_model.victim_organization, "Walmart")
        self.assertEqual(llm_response_model.victim_countries, ["United States"])
        self.assertEqual(llm_response_model.victim_industries, ["Retail"])
        self.assertEqual(llm_response_model.victim_regions, ["North America"])
        self.assertEqual(llm_response_model.intrusion_sets, ["Lazarus Group", "APT28"])
        self.assertEqual(llm_response_model.malware, [
            MalwareModel(name="AppleJeus", type="keylogger"),
            MalwareModel(name="Agent Tesla", type="rat")
            ])
        self.assertEqual(llm_response_model.tools, [
                "certutil",
                "BITSAdmin",
                "N/A",
                "PowerShell"
            ])
        self.assertEqual(llm_response_model.attack_patterns, 
            [
            AttackPatternModel(name="name", id="T0001")
            ])
        self.assertEqual(llm_response_model.vulnerabilities, [
                "CVE-2021-0001"
            ])
        self.assertEqual(llm_response_model.indicators, [
            IndicatorModel(type="file:hashes.MD5", value="0123456789abcdef0123456789abcdef")
            ])
        
        
        
    

if __name__ == '__main__':
    unittest.main()