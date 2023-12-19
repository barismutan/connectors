import unittest

from src.gpt_enrichment.builder import ResponseBundleBuilder
from stix2 import Identity,Report,ExternalReference,Relationship,Malware
import random


class TestLLMResponseModel(unittest.TestCase):
    def setUp(self): #Injecting dependencies
        self.author = "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
        self.author_identity=Identity(name="LLM")
        self.dummy_object=Identity(name="Dummy Object")
        self.report = {'id': '52bbf3b0-3343-448d-938e-f5c14401b278', 'standard_id': 'report--02d2dbba-e1a1-57eb-ae14-f90c15f37548', 'entity_type': 'Report', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Container'], 'spec_version': '2.1', 'created_at': '2023-11-21T12:04:58.225Z', 'updated_at': '2023-12-18T07:35:24.286Z', 'createdBy': None, 'objectMarking': [], 'objectLabel': [{'id': '282ca974-eda9-4853-a09e-f9c34586da61', 'value': 'gpt-enrichment-failed', 'color': 'FF0000', 'createdById': None}, {'id': '6665e631-f7da-4d58-b432-08297fe65e07', 'value': 'gpt-enrichment-success', 'color': '00FF00', 'createdById': None}], 'externalReferences': [{'id': '26ec6196-d5b8-4e53-b74c-f7da84476cd6', 'standard_id': 'external-reference--b1305ffa-06aa-5d2f-b488-791f951b9d03', 'entity_type': 'External-Reference', 'source_name': 'External', 'description': None, 'url': 'https://www.zscaler.com/blogs/security-research/ransomware-redefined-redenergy-stealer-ransomware-attacks', 'hash': None, 'external_id': None, 'created': '2023-11-21T12:04:53.605Z', 'modified': '2023-11-21T12:04:53.605Z', 'importFiles': [], 'createdById': None, 'importFilesIds': []}], 'revoked': False, 'x_opencti_reliability': None, 'confidence': 0, 'created': '2023-11-21T12:04:23.592Z', 'modified': '2023-12-18T07:35:24.286Z', 'name': 'https://www.zscaler.com/blogs/security-research/ransomware-redefined-redenergy-stealer-ransomware-attacks', 'description': None, 'report_types': None, 'published': '2023-11-21T12:04:23.592Z', 'objects': [], 'importFiles': [], 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': ['282ca974-eda9-4853-a09e-f9c34586da61', '6665e631-f7da-4d58-b432-08297fe65e07'], 'externalReferencesIds': ['26ec6196-d5b8-4e53-b74c-f7da84476cd6'], 'objectsIds': [], 'importFilesIds': []}
        self.external_references=[{'id': '26ec6196-d5b8-4e53-b74c-f7da84476cd6', 'standard_id': 'external-reference--b1305ffa-06aa-5d2f-b488-791f951b9d03', 'entity_type': 'External-Reference', 'source_name': 'External', 'description': None, 'url': 'https://www.zscaler.com/blogs/security-research/ransomware-redefined-redenergy-stealer-ransomware-attacks', 'hash': None, 'external_id': None, 'created': '2023-11-21T12:04:53.605Z', 'modified': '2023-11-21T12:04:53.605Z', 'importFiles': [], 'createdById': None, 'importFilesIds': []}]

    def test_indicator_malware_relationship_single_malware(self):
        data={
        "actor_motivation": [],
        "vulnerabilities": [],
        "ioc": [
            {
                "type": "file:hashes.MD5",
                "value": "fb7883d3fd9347debf98122442c2a33e"
            },
            {
                "type": "file:hashes.MD5",
                "value": "cb533957f70b4a7ebb4e8b896b7b656c"
            },
            {
                "type": "file:hashes.MD5",
                "value": "642dbe8b752b0dc735e9422d903e0e97"
            },
            {
                "type": "url",
                "value": "www[.]igrejaatos2[.]org/assets/programs/setupbrowser[.]exe"
            },
            {
                "type": "domain",
                "value": "2no[.]co"
            }
        ],
        "malware": [
            {
                "name": "RedEnergy stealer",
                "types": [
                    "stealer",
                    "ransomware"
                ]
            }
        ],
        "sectors": [
            "Energy",
            "Oil and Gas",
            "Telecom",
            "Machinery",
            "Manufacturing"
        ],
        "targeted_software": [],
        "intrusion_sets": [],
        "title": "Ransomware Redefined: RedEnergy Stealer-as-a-Ransomware attacks",
        "tools": [],
        "victim_countries": [
            "Philippines"
        ],
        "victim_organization": "Philippines Industrial Machinery Manufacturing Company",
        "victim_region": [
            "Asia"
        ],
        "observables":{
            "md5s":[
                "".join([random.choice(['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']) for _ in range(32)])
            ],
            "sha1s":[
                "".join([random.choice(['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']) for _ in range(40)])
            ],
            "sha256s":[
                "".join([random.choice(['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']) for _ in range(64)])
            ]
        }
            
    }
        # print("EXternal reference: ",self.external_references)
        builder=ResponseBundleBuilder(
                        llm_response=data,
                        author=self.author,
                        report=self.report,
                        external_references=self.external_references,
                        duplicate_report=False,
                        object_markings=[],
                        confidence=0,
                        author_identity=self.author_identity,
                    )
        bundle=builder.build()
        object_to_search=None
        for o in bundle.objects:
            if type(o)==Relationship:
                if o.source_ref.startswith("indicator--") and o.target_ref.startswith("malware--"):
                    object_to_search=o
                    print("Object to search: ",object_to_search)
                    break
                    
        malwares=[o for o in bundle.objects if type(o)==Malware]
        self.assertEqual(len(malwares),1)
        self.assertIsNotNone(object_to_search)
        
        
        
        
        
if __name__ == '__main__':
    unittest.main()
        