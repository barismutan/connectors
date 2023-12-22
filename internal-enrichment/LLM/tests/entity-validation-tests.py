import unittest
import stix2
import csv
import os
import yaml
from pycti import OpenCTIConnectorHelper, OpenCTIApiClient
from src.gpt_enrichment.entity_validation import EntityValidation


class TestEntityValidation(unittest.TestCase):
    def setUp(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (yaml.load(open(config_file_path), Loader=yaml.FullLoader)
                  if os.path.isfile(config_file_path) else {})
        
        opencti_helper = OpenCTIConnectorHelper(config)

        blacklist = []
        whitelist = []
        with open("tests/Blacklist.csv",'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                blacklist.append(row[0])

        with open("tests/Whitelist.csv",'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                whitelist.append(row[0])

        self.helper = opencti_helper
        self.whitelist = whitelist
        self.blacklist = blacklist
        self.entities = []


    def test_in_blacklist(self):
        entity1 = stix2.Malware(name = "Haskers Gang",
                                is_family = False) #name in blacklist
        
        self.entities = []
        self.entities.append(entity1)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()
        self.assertNotIn(entity1, result)



    def test_in_whitelist(self):
        entity1 = stix2.Malware(name = "Adwind",
                                is_family = False) #name in whitelist
        
        entity2 = stix2.Malware(name = "International",
                                is_family = False) #name in blacklist
        
        self.entities = []
        self.entities.append(entity1)
        self.entities.append(entity2)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()
        self.assertIn(entity1, result)
        self.assertNotIn(entity2, result)



    def test_in_whitelist_after_processing(self):
        entity1 = stix2.Malware(name = "Backdoor.SH.SHELLBOT",
                                is_family = False) #processed name(SHELLBOT) in whitelist
        
        self.entities = []
        self.entities.append(entity1)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()
        result_type = result[0]['type']
        result_name = result[0]['name']
        self.assertEqual(result_type, "malware")
        self.assertEqual(result_name, "SHELLBOT")

        

    def test_in_blacklist_after_processing(self):
        entity1 = stix2.Malware(name = "Manic Menagerie.SH",
                                is_family = False) #processed name(Manic Menagerie) in blacklist
        
        self.entities = []
        self.entities.append(entity1)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()
        self.assertEqual(result, [])
    


    def test_entity_type_malware_to_tool(self):
        entity1 = stix2.Malware(name = "chgrp",
                                is_family = False) #normally a tool
        
        self.entities = []
        self.entities.append(entity1)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()
        result_type = result[0]['type']
        result_name = result[0]['name']
        self.assertEqual(result_type, "tool")
        self.assertEqual(result_name, "chgrp")



    def test_entity_type_malware_to_intrusion_set(self):
        entity1 = stix2.Malware(name = "OnionDog",
                                is_family = False) #normally in intrusion set
        
        self.entities = []
        self.entities.append(entity1)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()

        result_type = result[0]['type']
        result_name = result[0]['name']
        result_label = result[0]['labels']
        self.assertEqual(result_type, "malware")
        self.assertEqual(result_name, "OnionDog")
        self.assertIsNotNone(result_label)

        label_value = result[1]['value'] #the value inside label
        self.assertEqual(label_value, "found-in-intrusion-set")



    def test_entity_type_tool_to_malware(self):
        entity1 = stix2.Tool(name = "Meltdown") #normally a malware
        
        self.entities = []
        self.entities.append(entity1)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()

        result_type = result[0]['type']
        result_name = result[0]['name']
        self.assertEqual(result_type, "malware")
        self.assertEqual(result_name, "Meltdown")


    def test_entity_type_tool_to_intrusion_set(self):
        entity1 = stix2.Tool(name = "OnionDog") #normally in intrusion set
        
        self.entities = []
        self.entities.append(entity1)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()

        result_type = result[0]['type']
        result_name = result[0]['name']
        result_label = result[0]['labels']
        self.assertEqual(result_type, "tool")
        self.assertEqual(result_name, "OnionDog")
        self.assertIsNotNone(result_label)

        label_value = result[1]['value'] #the value inside label
        self.assertEqual(label_value, "found-in-intrusion-set")



    def test_entity_type_intrusion_set_to_malware(self):
        entity1 = stix2.IntrusionSet(name = "Meltdown") #normally in intrusion set
        
        self.entities = []
        self.entities.append(entity1)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()

        result_type = result[0]['type']
        result_name = result[0]['name']
        result_label = result[0]['labels']
        self.assertEqual(result_type, "intrusion-set")
        self.assertEqual(result_name, "Meltdown")
        self.assertIsNotNone(result_label)

        label_value = result[1]['value'] #the value inside label
        self.assertEqual(label_value, "found-in-malware")



    def test_entity_type_intrusion_set_to_tool(self):
        entity1 = stix2.IntrusionSet(name = "chgrp") #normally in intrusion set
        
        self.entities = []
        self.entities.append(entity1)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()

        result_type = result[0]['type']
        result_name = result[0]['name']
        result_label = result[0]['labels']
        self.assertEqual(result_type, "intrusion-set")
        self.assertEqual(result_name, "chgrp")
        self.assertIsNotNone(result_label)

        label_value = result[1]['value'] #the value inside label
        self.assertEqual(label_value, "found-in-tool")



    def test_entity_not_found_anywhere(self):
        entity1 = stix2.Malware(name = "abcdefg12",
                                is_family = False) #just a random name
        entity2 = stix2.Tool(name = "abcdefg12") #just a random name
        entity3 = stix2.IntrusionSet(name = "abcdefg12") #just a random name
        
        self.entities = []
        self.entities.append(entity1)
        self.entities.append(entity2)
        self.entities.append(entity3)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()

        self.assertEqual("abcdefg12", result[0]['name']) #"not found" data is accepted as is with 0 confidence
        self.assertEqual("abcdefg12", result[1]['name'])
        self.assertEqual("abcdefg12", result[2]['name'])
        self.assertEqual("malware", result[0]['type']) #"not found" data is accepted as is with 0 confidence
        self.assertEqual("tool", result[1]['type'])
        self.assertEqual("intrusion-set", result[2]['type'])


    def test_entity_name_is_cve(self):
        entity1 = stix2.Malware(name = "DOCX/CVE-2017-11882",
                                is_family = False) #CVE as name
        entity2 = stix2.Tool(name = "Exploit.Xml.CVE-2017-0199")
        entity3 = stix2.IntrusionSet(name = "CVE-2017-11882")
        
        self.entities = []
        self.entities.append(entity1)
        self.entities.append(entity2)
        self.entities.append(entity3)

        entity_validation_object = EntityValidation(whitelist=self.whitelist, 
                                                    blacklist=self.blacklist,
                                                    entities=self.entities,
                                                    opencti_helper=self.helper)
        
        result = entity_validation_object.entity_validation()

        self.assertIn(entity1, result) #CVEs are accepted as is
        self.assertIn(entity2, result)
        self.assertIn(entity3, result)

    def tearDown(self):
        del self.helper

    


if __name__ == '__main__':
    unittest.main(exit= False)
    print("hello")