import re
import json
from pycti import OpenCTIConnectorHelper
class Postprocessor:
    def __init__(self,helper: OpenCTIConnectorHelper):
        super().__init__() #this is not used for now. Idea is to create a TextProcessor class and have Preprocessor and Postprocessor inherit from it.
        self.emptyish=[
            "None",
            "none",
            "N/A",
            "n/a",
            "NA",
            "na",
            "N/a",
            "N\A",
            "Unknown",
            "unknown",
            "null",
            "Null",
            "NULL",
            ""

        ]
        emptyish_list_no_quote=["[{}]".format(emptyish) for emptyish in self.emptyish]
        emptyish_list_double_quote=["[\"{}\"]".format(emptyish) for emptyish in self.emptyish]
        emptyish_list_single_quote=["['{}']".format(emptyish) for emptyish in self.emptyish]
        self.emptyish+=emptyish_list_no_quote+emptyish_list_double_quote+emptyish_list_single_quote
        self.helper=helper
        self.prompt_to_stix={
            "CVE":"vulnerabilities",
            "cves":"vulnerabilities",#TODO: not ideal
            "cve":"vulnerabilities",#TODO: not ideal
            "ttps":"attack_patterns",#TODO: not ideal
            "TTP":"attack_patterns",
            "ttp":"attack_patterns",
            "IoC":"indicators",
            "ioc":"indicators",
            "victim_location":"locations",
            "threat_actor":"intrusion_sets",
            "sectors":"sectors",
            "Title":"title",
            "Victim Country":"victim_country",
            "Victim Region":"victim_region",
            "Sectors":"sectors",
            "Threat Actors":"intrusion_sets",
            "threat_actor":"intrusion_sets",
            "threat_actors":"intrusion_sets",
            "Actor Motivation":"actor_motivation",
            "Malware":"malware",
            "Tools":"tools",
            "Targeted Software":"software",
            "targeted_software":"software",
            "Victim Organization":"victim_organization",
            }
        
        self.str_fields=[
            "title",
            "victim_organization"
        ]
        
        self.file_extensions=[
            "exe",
            "dll",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "ppt",
            "pptx",
            "pdf",
            "txt",
            "zip",
            "rar",
            "7z",
            "gz",
            "tar",
            "iso",
            "elf",
            "bin",

        ]


    

    def map_prompt_field_to_stix_field(self, field : str) -> str:
        return self.prompt_to_stix[field] if field in self.prompt_to_stix.keys() else field

    def postprocess(self, blog : str,map_prompt_field_to_stix_field: bool = True) -> dict:
        #TODO: add filtering here to get rid of filenames ".exe,.dll etc."
        #TODO: add object speficic postprocessing here
        try:
            try:
                blog=json.loads(blog)
            except json.decoder.JSONDecodeError as e:
                # self.helper.log_error(f"Error while decoding JSON: {e}")
                raise self.InvalidLLMResponseException(blog)
            
            output={}
            # self.helper.log_debug(f"DEBUG DEBUG: Blog before postprocessing: \n\n {blog} \n\n")
            blog=self.lowercase_keys_recursive(blog)
            blog=self.underscore_keys_recursive(blog)
            # print("Blog after lowercase and underscore: " + str(blog))
            self.helper.log_debug(f"Blog after lowercase and underscore: \n\n {blog} \n\n")

            for field in blog.keys():
                #making sure the keys are standardized
                if map_prompt_field_to_stix_field and field not in self.prompt_to_stix.values():
                    output_field=self.map_prompt_field_to_stix_field(field)
                else:
                    output_field=field
                # print("Output field: " +output_field)
                #making sure the fields we expect as lists come out as lists and emptyish strings are converted to empty strings.
                if output_field not in self.str_fields:
                    blog[field]=self.convert_empty_str_to_list(blog[field])
                    # blog[output_field]=self.convert_str_to_list(blog[output_field]) #TODO: this is a very unexpected case.
                if output_field in self.str_fields:
                    if self.check_str_in_emptyish(blog[field]):
                        blog[field]=""
                
                #remove emptyish strings from lists
                if output_field not in self.str_fields:
                    blog[field]=self.remove_emptyish_strings(blog[field])


                

                # field=field.lower()
                # print("Blog after lowercase: " + str(blog))

                if output_field=="title":
                    output[output_field]=self.postprocess_title_field(blog[field])
                elif output_field=="victim_country":
                    output[output_field]=self.postprocess_victim_country_field(blog[field])
                elif output_field=="victim_region":
                    output[output_field]=self.postprocess_victim_region_field(blog[field])
                elif output_field=="sectors":
                    output[output_field]=self.postprocess_sectors_field(blog[field])
                elif output_field=="victim_organization":
                    # print("Victim organization: " + str(blog[output_field]))
                    output[output_field]=self.postprocess_victim_field(blog[field])
                elif output_field=="intrusion_sets":
                    output[output_field]=self.postprocess_threat_actor_field(blog[field])
                elif output_field=="actor_motivation":
                    output[output_field]=self.postprocess_actor_motivation_field(blog[field])
                elif output_field=="malware":
                    output[output_field]=self.postprocess_malware_field(blog[field])
                elif output_field=="tools":
                    output[output_field]=self.postprocess_tools_field(blog[field])
                elif output_field=="software":
                    output[output_field]=self.postprocess_software_field(blog[field])
                elif output_field=="vulnerabilities":
                    output[output_field]=self.postprocess_vulnerabilities_field(blog[field])
                elif output_field=="attack_patterns":
                    output[output_field]=self.postprocess_ttp_field(blog[field])
                elif output_field=="indicators":
                    output[output_field]=self.postprocess_ioc_field(blog[field])
                else:
                    # self.helper.log_error(f"Unknown field {field}")
                    raise self.PostProcessingException(f"Unknown field {field}")
                    #TODO: the list should be checked against all valid STIX types.
                    #Ones matching should be logged as WARNING. Others should be logged as ERROR.

            output=self.lowercase_keys(output)
            # print("Final output:")
            # print(json.dumps(output,indent=4))
            self.helper.log_debug(f"Final output: \n\n {json.dumps(output,indent=4)} \n\n")
            return output
        except Exception as e:
            raise self.PostProcessingException(f"Error while postprocessing: {e}")

    # @DeprecationWarning
    def postprocess_str_field(self, field : str) -> str:
        return [] if self.convert_empty_str_to_list(field)==[] else self.convert_str_to_list(field)

    # @DeprecationWarning
    def convert_str_to_list(self, string : str) -> list:
        # self.helper.log_debug(f"DEBUG DEBUG: Converting string \n\n {string} \n\nto list")
        return [item.strip() for item in string.split(",")]
    
    # @DeprecationWarning
    def convert_empty_str_to_list(self, string : str) -> list:
        return [] if self.check_str_in_emptyish(string) else string
    
    def check_str_in_emptyish(self, string : str) -> bool:
        return True if string in self.emptyish else False
    
    def remove_emptyish_strings(self, liste : list) -> list:
        if len(liste)==0:
            return liste#Trivial case
        else:
            if type(liste[0])==str:
                return [item for item in liste if not self.check_str_in_emptyish(item)]
            elif type(liste[0])==dict:
                # return [item for item in liste if not any([self.check_str_in_emptyish(str(item[key])) for key in item.keys()])] #this deletes the item altogether
                new_items=[]
                for item in liste:
                    for key in item.keys():
                        if self.check_str_in_emptyish(str(item[key])):
                            item[key]="" if type(item[key])==str else []
                    new_items.append(item)
                return new_items

            else:
                raise self.PostProcessingException(f"Unknown type in list: {type(liste[0])}")
    
    def remove_emptyish_strings_dict(self,dictionary : dict) -> dict:
        pass#TODO: implement this
        
    

    def lowercase_keys(self, blog : dict) -> dict:
        return {key.lower():blog[key] for key in blog.keys()}
    
    def lowercase_keys_recursive(self, blog : dict) -> dict:
        '''
        Recursively lowercases all keys in a dictionary.
        '''
        output={}
        for key in blog.keys():
            if type(blog[key])==dict:
                output[key.lower()]=self.lowercase_keys_recursive(blog[key])
            else:
                output[key.lower()]=blog[key]
        return output
    
    def underscore_keys_recursive(self, blog : dict) -> dict:
        '''
        Recursively replaces spaces in keys with underscores.
        '''
        output={}
        for key in blog.keys():
            if type(blog[key])==dict:
                output[key.replace(" ","_")]=self.underscore_keys_recursive(blog[key])
            else:
                output[key.replace(" ","_")]=blog[key]
        return output
    

    def postprocess_title_field(self, title : str) -> str:
        if type(title)==str:
            return title
        raise self.PostProcessingException(f"Title field is not a string: {title}")
    
    def postprocess_victim_country_field(self, victim_country : list[str]) -> list[str]:
        if type(victim_country)==list and all(isinstance(item, str) for item in victim_country):
            return victim_country
        raise self.PostProcessingException(f"Victim country field is not a list of strings: {victim_country} has type {type(victim_country)}")
    
    def postprocess_victim_region_field(self, victim_region : list[str]) -> list[str]:
        if type(victim_region)==list and all(isinstance(item, str) for item in victim_region):
            return victim_region
        raise self.PostProcessingException(f"Victim region field is not a list of strings: {victim_region}")
    
    def postprocess_sectors_field(self, sectors : list[str]) -> list[str]:
        if type(sectors)==list and all(isinstance(item, str) for item in sectors):
            return sectors
        raise self.PostProcessingException(f"Sectors field is not a list of strings: {sectors}")
    
    def postprocess_threat_actor_field(self, threat_actors : list[dict]) -> list[dict]:
        if type(threat_actors)==list and all(isinstance(item, dict) for item in threat_actors):
            for element in threat_actors:
                list_of_keys=list(element.keys())
                if len(list_of_keys)!=2:
                    raise self.PostProcessingException(f"A threat actor object does not have two keys: {element}")
                if "name" not in list_of_keys:
                    raise self.PostProcessingException(f"A threat actor object does not have a name key: {element}")
                if "aliases" not in list_of_keys:
                    raise self.PostProcessingException(f"A threat actor object does not have a aliases key: {element}")
                if type(element["name"])!=str:
                    raise self.PostProcessingException(f"A threat actor object's name field is not a string: {element}")
                if type(element["aliases"])!=list and not all(isinstance(item, str) for item in element["aliases"]):
                    raise self.PostProcessingException(f"A threat actor object's name field is not a list of strings: {element}")
                
            return threat_actors
        else:
            raise self.PostProcessingException(f"Threat actor field is not a list of dictionaries: {threat_actors}")

    def postprocess_actor_motivation_field(self, actor_motivation : list[str]) -> list[str]:
        if type(actor_motivation)==list and all(isinstance(item, str) for item in actor_motivation):
            return actor_motivation
        raise self.PostProcessingException(f"Actor motivation field is not a list of strings: {actor_motivation}")
    
    def postprocess_malware_field(self, malware : list[dict]) -> list[dict]:
        if type(malware)==list and all(isinstance(item, dict) for item in malware):
            for element in malware:
                list_of_keys=list(element.keys())
                if len(list_of_keys)!=2:
                    raise self.PostProcessingException(f"A malware object does not have two keys: {element}")
                if "name" not in list_of_keys:
                    raise self.PostProcessingException(f"A malware object does not have a name key: {element}")
                if "types" not in list_of_keys:
                    raise self.PostProcessingException(f"A malware object does not have a types key: {element}")
                if type(element["name"])!=str:
                    raise self.PostProcessingException(f"A malware object's name field is not a string: {element}")
                if type(element["types"])!=list and not all(isinstance(item, str) for item in element["types"]):
                    raise self.PostProcessingException(f"A malware object's types field is not a list of strings: {element}")
                
            return malware
        else:
            raise self.PostProcessingException(f"Malware field is not a list of dictionaries: {malware}")
        
    def postprocess_tools_field(self, tools : list[str]) -> list[str]:
        if type(tools)==list and all(isinstance(item, str) for item in tools):
            return tools
        raise self.PostProcessingException(f"Tools field is not a list of strings: {tools}")
    
    def postprocess_software_field(self, software : list[dict]) -> list[dict]:
        if type(software)==list and all(isinstance(item, dict) for item in software):
            for element in software:
                list_of_keys=list(element.keys())
                if len(list_of_keys)!=2:
                    raise self.PostProcessingException(f"A software object does not have two keys: {element}")
                if "name" not in list_of_keys:
                    raise self.PostProcessingException(f"A software object does not have a name key: {element}")
                if "versions" not in list_of_keys:
                    raise self.PostProcessingException(f"A software object does not have a versions key: {element}")
                if type(element["name"])!=str:
                    raise self.PostProcessingException(f"A software object's name field is not a string: {element}")
                if type(element["versions"])!=list and not all(isinstance(item, str) for item in element["versions"]):
                    raise self.PostProcessingException(f"A software object's versions field is not a list of strings: {element}")
                
            return software
        else:
            raise self.PostProcessingException(f"Software field is not a list of dictionaries: {software}")
        
    def postprocess_vulnerabilities_field(self, vulnerabilities : list[str]) -> list[str]:
        if type(vulnerabilities)==list and all(isinstance(item, str) for item in vulnerabilities):
            return vulnerabilities
        raise self.PostProcessingException(f"Vulnerabilities field is not a list of strings: {vulnerabilities}")
    
    def postprocess_ttp_field(self, ttps : list[dict]) -> list[dict]:
        if type(ttps) == list and all(isinstance(item, dict) for item in ttps):
            for element in ttps:
                list_of_keys=list(element.keys())
                if len(list_of_keys)!=2:
                    raise self.PostProcessingException(f"A TTP object does not have two keys: {element}")
                if "name" not in list_of_keys:
                    if "Technique Name" in list_of_keys:
                        element["name"]=element["Technique Name"]
                        list_of_keys.append("name")
                        element.pop("Technique Name")#Hardcoding for possible misspelling in LLM
                    else:
                        raise self.PostProcessingException(f"A TTP object does not have a name key: {element}")
                    
                if "id" not in list_of_keys:
                    if "Technique ID" in list_of_keys:
                        element["id"]=element["Technique ID"]
                        list_of_keys.append("id")
                        element.pop("Technique ID")
                    else:
                        raise self.PostProcessingException(f"A TTP object does not have a id key: {element}")
                    
                if type(element["name"])!=str:
                    raise self.PostProcessingException(f"A TTP object's name field is not a string: {element}")
                if type(element["id"])!=str:
                    raise self.PostProcessingException(f"A TTP object's id field is not a string: {element}")
                
            return ttps
        else:
            raise self.PostProcessingException(f"TTP field is not a list of dictionaries: {ttps}")
        
    def postprocess_ioc_field(self, iocs : list[dict]) -> list[dict]:
        if type(iocs)==list and all(isinstance(item, dict) for item in iocs):
            for element in iocs:
                list_of_keys=list(element.keys())
                if len(list_of_keys)!=2:
                    raise self.PostProcessingException(f"An IOC object does not have two keys: {element}")
                if "type" not in list_of_keys:
                    raise self.PostProcessingException(f"An IOC object does not have a type key: {element}")
                if "value" not in list_of_keys:
                    raise self.PostProcessingException(f"An IOC object does not have a value key: {element}")
                if type(element["type"])!=str:
                    raise self.PostProcessingException(f"An IOC object's type field is not a string: {element}")
                if type(element["value"])!=str:
                    raise self.PostProcessingException(f"An IOC object's value field is not a string: {element}")
                
            return iocs
        else:
            raise self.PostProcessingException(f"IOC field is not a list of dictionaries: {iocs}")
        
    def postprocess_victim_field(self, victim: str) -> str:
        if type(victim)==str:
            return victim
        raise self.PostProcessingException(f"Victim field is not a string: {victim}")




    class InvalidLLMResponseException(Exception): #TODO: move this to a separate file along with the other exceptions
        def __init__(self, invalid_response : str):
            super().__init__("LLM returned the following invalid response: {}".format(invalid_response))
    
    class PostProcessingException(Exception):
        def __init__(self, message):
            super().__init__(message)
    

    
    

