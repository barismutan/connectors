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

        ]
        emptyish_list_no_quote=["[{}]".format(emptyish) for emptyish in self.emptyish]
        emptyish_list_double_quote=["[\"{}\"]".format(emptyish) for emptyish in self.emptyish]
        emptyish_list_single_quote=["['{}']".format(emptyish) for emptyish in self.emptyish]
        self.emptyish+=emptyish_list_no_quote+emptyish_list_double_quote+emptyish_list_single_quote
        self.helper=helper
        self.prompt_to_stix={
            "CVE":"vulnerabilities",
            "TTP":"attack_patterns",
            "IoC":"indicators",
            "victim_location":"locations",
            "threat_actor":"intrusion_sets",
            "sectors":"sectors"
            }
        
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

    def postprocess(self, blog : str) -> dict:
        #TODO: add filtering here to get rid of filenames ".exe,.dll etc."
        #TODO: add object speficic postprocessing here
        try:
            try:
                blog=json.loads(blog)
            except json.decoder.JSONDecodeError as e:
                self.helper.log_error(f"Error while decoding JSON: {e}")
                raise self.InvalidLLMResponseException(blog)
            
            output={}
            self.helper.log_debug(f"DEBUG DEBUG: Blog before postprocessing: \n\n {blog} \n\n")

            for field in blog.keys():
                output_field=self.map_prompt_field_to_stix_field(field)
                if output_field=="title":
                    output[output_field]=self.postprocess_title_field(blog[field])
                elif output_field=="victim_country":
                    output[output_field]=self.postprocess_victim_country_field(blog[field])
                elif output_field=="victim_region":
                    output[output_field]=self.postprocess_victim_region_field(blog[field])
                elif output_field=="sectors":
                    output[output_field]=self.postprocess_sectors_field(blog[field])
                elif output_field=="threat_actor":
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
                    self.helper.log_error(f"Unknown field {field}")
                    raise self.PostProcessingException(f"Unknown field {field}")
                    #TODO: the list should be checked against all valid STIX types.
                    #Ones matching should be logged as WARNING. Others should be logged as ERROR.

            output=self.lowercase_keys(output)
            return output
        except Exception as e:
            raise self.PostProcessingException(f"Error while postprocessing: {e}")

    @DeprecationWarning
    def postprocess_str_field(self, field : str) -> str:
        return [] if self.convert_empty_str_to_list(field)==[] else self.convert_str_to_list(field)

    @DeprecationWarning
    def convert_str_to_list(self, string : str) -> list:
        self.helper.log_debug(f"DEBUG DEBUG: Converting string \n\n {string} \n\nto list")
        return [item.strip() for item in string.split(",")]
    
    @DeprecationWarning
    def convert_empty_str_to_list(self, string : str) -> list:
        return [] if string in self.emptyish else string
    
    @DeprecationWarning
    def lowercase_keys(self, blog : dict) -> dict:
        return {key.lower():blog[key] for key in blog.keys()}
    

    def postprocess_title_field(self, title : str) -> str:
        if type(title)==str:
            return title
        raise self.PostProcessingException(f"Title field is not a string: {title}")
    
    def postprocess_victim_country_field(self, victim_country : list[str]) -> list[str]:
        if type(victim_country)==list[str]:
            return victim_country
        raise self.PostProcessingException(f"Victim country field is not a list of strings: {victim_country}")
    
    def postprocess_victim_region_field(self, victim_region : list[str]) -> list[str]:
        if type(victim_region)==list[str]:
            return victim_region
        raise self.PostProcessingException(f"Victim region field is not a list of strings: {victim_region}")
    
    def postprocess_sectors_field(self, sectors : list[str]) -> list[str]:
        if type(sectors)==list[str]:
            return sectors
        raise self.PostProcessingException(f"Sectors field is not a list of strings: {sectors}")
    
    def postprocess_threat_actor_field(self, threat_actors : list[dict]) -> list[dict]:
        if type(threat_actors)==list[dict]:
            for element in threat_actors:
                list_of_keys=list(element.keys())
                if len(list_of_keys)!=2:
                    raise self.PostProcessingException(f"A threat actor object does not have two keys: {element}")
                if "name" not in list_of_keys:
                    raise self.PostProcessingException(f"A threat actor object does not have a name key: {element}")
                if "aliases" not in list_of_keys:
                    raise self.PostProcessingException(f"A threat actor object does not have a aliases key: {element}")
                if type(element["threat_actor"])!=str:
                    raise self.PostProcessingException(f"A threat actor object's threat_actor field is not a string: {element}")
                if type(element["threat_actor_aliases"])!=list[str]:
                    raise self.PostProcessingException(f"A threat actor object's threat_actor_aliases field is not a list of strings: {element}")
                
            return threat_actors
        else:
            raise self.PostProcessingException(f"Threat actor field is not a list of dictionaries: {threat_actors}")

    def postprocess_actor_motivation_field(self, actor_motivation : list[str]) -> list[str]:
        if type(actor_motivation)==list[str]:
            return actor_motivation
        raise self.PostProcessingException(f"Actor motivation field is not a list of strings: {actor_motivation}")
    
    def postprocess_malware_field(self, malware : list[dict]) -> list[dict]:
        if type(malware)==list[dict]:
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
                if type(element["types"])!=list[str]:
                    raise self.PostProcessingException(f"A malware object's types field is not a list of strings: {element}")
                
            return malware
        else:
            raise self.PostProcessingException(f"Malware field is not a list of dictionaries: {malware}")
        
    def postprocess_tools_field(self, tools : list[str]) -> list[str]:
        if type(tools)==list[str]:
            return tools
        raise self.PostProcessingException(f"Tools field is not a list of strings: {tools}")
    
    def postprocess_software_field(self, software : list[dict]) -> list[dict]:
        if type(software)==list[dict]:
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
                if type(element["versions"])!=list[str]:
                    raise self.PostProcessingException(f"A software object's versions field is not a list of strings: {element}")
                
            return software
        else:
            raise self.PostProcessingException(f"Software field is not a list of dictionaries: {software}")
        
    def postprocess_vulnerabilities_field(self, vulnerabilities : list[str]) -> list[str]:
        if type(vulnerabilities)==list[str]:
            return vulnerabilities
        raise self.PostProcessingException(f"Vulnerabilities field is not a list of strings: {vulnerabilities}")
    
    def postprocess_ttp_field(self, ttps : list[dict]) -> list[dict]:
        if type(ttps) == list[dict]:
            for element in ttps:
                list_of_keys=list(element.keys())
                if len(list_of_keys)!=2:
                    raise self.PostProcessingException(f"A TTP object does not have two keys: {element}")
                if "name" not in list_of_keys:
                    raise self.PostProcessingException(f"A TTP object does not have a name key: {element}")
                if "id" not in list_of_keys:
                    raise self.PostProcessingException(f"A TTP object does not have a id key: {element}")
                if type(element["name"])!=str:
                    raise self.PostProcessingException(f"A TTP object's name field is not a string: {element}")
                if type(element["id"])!=str:
                    raise self.PostProcessingException(f"A TTP object's id field is not a string: {element}")
                
            return ttps
        else:
            raise self.PostProcessingException(f"TTP field is not a list of dictionaries: {ttps}")
        
    def postprocess_ioc_field(self, iocs : list[dict]) -> list[dict]:
        if type(iocs)==list[dict]:
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
        





    class InvalidLLMResponseException(Exception): #TODO: move this to a separate file along with the other exceptions
        def __init__(self, invalid_response : str):
            super().__init__("LLM returned the following invalid response: {}".format(invalid_response))
    
    class PostProcessingException(Exception):
        def __init__(self, message):
            super().__init__(message)
    

    
    

