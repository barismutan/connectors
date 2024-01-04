from typing import List,Union
from pycti import OpenCTIConnectorHelper
import stix2
import re

class EntityValidation:
    def __init__(self, whitelist:List[str], blacklist:List[str], entities:List[Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]], opencti_helper:OpenCTIConnectorHelper): #constructor
        """
        Creates the object of the EntityValidation class which is used to do the entity validation process.
        
        Parameters:
            whitelist (List[str]): Whitelist as a list of strings.
            blacklist (List[str]): Blacklist as a list of strings. 
            entities (List[Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]]): Entities as a list of stix objects.
        
        Returns:
            None
        """

        __whitelist = []
        __blacklist = []
        for keyword_whitelist in whitelist:
            __whitelist.append(keyword_whitelist.casefold())

        for keyword_blacklist in blacklist:
            __blacklist.append(keyword_blacklist.casefold())

        self.__whitelist = __whitelist
        self.__blacklist = __blacklist
        self.entities = entities
        self.opencti_helper = opencti_helper
        self.created_labels = []
    

    def __is_cve(self, entity_name:str) -> bool: #CVE's will be present as it is.
        #returns: True -> entity name is a CVE
        #         False -> entity name is not a CVE

        regex_cve = re.compile("^CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]+$")

        splitted_data = re.split(r'[:.#![\]%_()/\\ ]', entity_name)
        for i in splitted_data:
            if regex_cve.match(i):
                return True
        return False


    def __extract_path_from_name(self, entitiy_name:str) -> str: #analyse data with seperating it just with <space> and see if there is a path in data.
        #returns: str -> the name of the entity without a path in it.

        result = ''
        splitted_data = re.split(r'[ ]', entitiy_name)
        regex_path = re.compile("[a-fA-F]+:.*\..*") #Paths

        for element in splitted_data:
            if not regex_path.match(element):
                if len(result) > 0:
                    result = result + " "
                result = result + str(element)
        return result


    def __search_in_whitelist(self, entity_name:str) -> bool: #search entity name in the given whitelist
        #returns: True -> whitelist contains the entity name
        #         False -> whitelist does not contain the entity name

        if self.__whitelist.__contains__(entity_name.casefold()):
            return True
        return False


    def __search_in_blacklist(self, entity_name:str) -> bool: #search entity name in the given blacklist
        #returns: True -> blacklist contains the entity name
        #         False -> blacklist does not contain the entity name

        if self.__blacklist.__contains__(entity_name.casefold()):
            return True
        return False


    def __is_matching_with_regex_rules(self, word:str) -> bool: #try to find a match between the regex rules nad the given word(string)
        #returns: True -> given word(string) is matching with at least one regex
        #         False -> given word(string) is not matching with any of the regex

        regex_mitre_no = re.compile("[Ss][0-9][0-9][0-9][0-9]") #MITRE no
        regex_del_1 = re.compile("^[a-zA-Z][0-9][0-9][0-9][0-9][0-9][0-9]$") #One character + 6 numbers
        regex_del_2 = re.compile("^[a-zA-Z][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$") #One character + 7 numbers
        regex_del_3 = re.compile("[0-9][0-9][0-9]+") #Number that contains at least 3 digits in it (2+ digits)
        regex_hash_32 = re.compile("[0-9a-fA-F]{32}") #Hash values - 32 bits
        regex_hash_40 = re.compile("[0-9a-fA-F]{40}") #Hash values - 40 bits
        regex_hash_64 = re.compile("[0-9a-fA-F]{64}") #Hash values - 64 bits

        if regex_mitre_no.match(word) or regex_del_1.match(word) or regex_del_2.match(word) or regex_del_3.match(word) or regex_hash_32.match(word) or regex_hash_40.match(word) or regex_hash_64.match(word):
            return True
        return False


    def __extract_blacklist_keywords(self, entity_name_splitted:List[str]) -> List[str]: #search entity name in the given blacklist
        #returns: List[str] -> entity name splitted as list of strings that is cleaned with blacklist keywords and regex rules
        
        result = []
        for i in range(len(entity_name_splitted)):
            if len(entity_name_splitted[i]) > 0:
                found_in_blacklist = self.__search_in_blacklist(entity_name_splitted[i])
                if not found_in_blacklist:
                    match_with_regex_rules = self.__is_matching_with_regex_rules(entity_name_splitted[i])
                    if not match_with_regex_rules:
                        result.append(entity_name_splitted[i])

        if result != [] and len(result[0]) < 2: #Reject the entities that only contains a (1) charachter.
            result = []

        return result


    def __process_entity(self, entity_name:str) -> str: #process the entity name according to rules (using regex and blacklist)
        #returns: str -> the name of the entity after the cleaning process
        
        result = ''
        splitted_data = re.split(r'[-@:.#![\]%_()/\\ ]', entity_name)
        splitted_data = self.__extract_blacklist_keywords(splitted_data)

        if len(splitted_data) > 0:
            if len(splitted_data) > 3: #Reject the data that has 3+ words in it
                result = ''
            else:
                splitted_data = ' '.join(splitted_data)
                result = splitted_data

        regex_number = re.compile("[0-9]+") #Reject the data that contains only number(s)
        if regex_number.match(result):
            result = ''
        return result


    def __search_in_malware(self, entity_name:str) -> bool: #search the given name in malware data in database
        #returns: True -> entity name is found in malware
        #         False -> entity name is not found in malware

        found_in_malware = self.opencti_helper.api.malware.read(
            filters=[{"key": "name", "values": [entity_name]}]
        )

        found_in_malware_aliases = self.opencti_helper.api.malware.read(
            filters=[{"key": "aliases", "values": [entity_name]}]
        )

        if (found_in_malware is None) and (found_in_malware_aliases is None):
            return False
        return True



    def __search_in_tool(self, entity_name:str) -> bool: #search the given name in tool data in database
        #returns: True -> entity name is found in tool
        #         False -> entity name is not found in tool
        
        found_in_tool = self.opencti_helper.api.tool.read(
            filters=[{"key": "name", "values": [entity_name]}]
        )

        if found_in_tool is None:
            return False
        return True


    def __search_in_intrusion_set(self, entity_name:str) -> bool: #search the given name in intrusion set data in database
        #returns: True -> entity name is found in intrusion set
        #         False -> entity name is not found in intrusion set
        
        found_in_intrusion_set = self.opencti_helper.api.intrusion_set.read(
            filters=[{"key": "name", "values": [entity_name]}]
        )

        if found_in_intrusion_set is None:
            return False
        return True


    def __change_type_to_malware(self, entity:Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]) -> Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]: #change the type of the given entity to malware
        #returns: Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject] -> object that its type changed to malware
        entity_new_version = stix2.Malware(name=entity['name'],
                                           is_family = False)
        return entity_new_version


    def __change_type_to_tool(self, entity:Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]) -> Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]: #change the type of the given entity to tool
        #returns: Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject] -> object that its type changed to malware
        entity_new_version = stix2.Tool(name=entity['name'])
        return entity_new_version


    def __change_type_to_intrusion_set(self, entity:Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]) -> Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]: #change the type of the given entity to intrusion set
        #returns: Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject] -> object that its type changed to malware
        entity_new_version = stix2.IntrusionSet(name=entity['name'])
        return entity_new_version
    
    
    '''
    def __change_confidence(self, entity:Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject], new_confidence:int) -> Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]: #change the confidence of the given entity
        #returns: Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject] -> object that its confidence is changed to the given confidence(as a parameter)
        entity_new_version = entity.new_version(confidence=new_confidence)
        return entity_new_version
    '''


    def __arrange_entity_type(self, entity:Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]) -> Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]: #search the given name in other types of data in database
        #returns: stix2.v21.Identity object -> entity that is searched in other types(type changing process is done here)
        
        entity_name = entity['name']
        entity_type = entity['type']

        if entity_type == "malware": #If the entity type is malware, search the entity name in tool and intrusion set respectively.
            found_in_tool = self.__search_in_tool(entity_name)
            if found_in_tool:
                entity_updated = self.__change_type_to_tool(entity) #Found -> change type to tool and accept the entity.
                return entity_updated
            
            #Not found -> search in intrusion set.
            found_in_intrusion_set = self.__search_in_intrusion_set(entity_name)
            if found_in_intrusion_set: 
                #TODO
                #set confidence to 0.
                #entity_updated_confidence = self.__change_confidence(entity, 0)

                #create the label "found-in-intrusion-set" and add it to the entity.
                

                entity_updated = entity.new_version(labels = ["found-in-intrusion-set"])

                #accept the data as it is.
                return entity_updated
            return None #Not found in other types too.
        

        if entity_type == "tool": #If the entity type is tool, search the entity name in malware and intrusion set respectively.
            found_in_malware = self.__search_in_malware(entity_name)
            if found_in_malware:
                entity_updated = self.__change_type_to_malware(entity) #Found -> change type to malware and accept the entity.
                return entity_updated
            
            #Not found -> search in intrusion set.
            found_in_intrusion_set = self.__search_in_intrusion_set(entity_name)
            if found_in_intrusion_set: 
                #TODO
                #set confidence to 0.

                #entity_updated_confidence = self.__change_confidence(entity, 0)
                #create the label "found-in-intrusion-set" and add it to the entity.
                
                
                entity_updated = entity.new_version(labels = ["found-in-intrusion-set"])

                #accept the data as it is.
                return entity_updated
            return None #Not found in other types too.
        

        if entity_type == "intrusion-set": #If the entity type is intrusion set, search the entity name in malware and tool respectively.
            found_in_malware = self.__search_in_malware(entity_name)
            if found_in_malware: 
                #TODO
                #set confidence to 0.
                #entity_updated_confidence = self.__change_confidence(entity, 0)

                

                entity_updated = entity.new_version(labels = ["found-in-intrusion-set"])

                #accept the data as it is.
                return entity_updated
            
            #Not found -> search in tool.
            found_in_tool = self.__search_in_tool(entity_name)
            if found_in_tool: 
                #TODO
                #set confidence to 0.
                #entity_updated_confidence = self.__change_confidence(entity, 0)



                entity_updated = entity.new_version(labels = ["found-in-tool"])

                #accept the data as it is.
                return entity_updated
            return None #Not found in other types too.
        

    def entity_validation(self) -> List[Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]]: #This function is used to call the process outside of the class.
        """
        This method helps to do the validation process of the entities, using the methods of comparison with whitelist and blacklist, and clearing the distractive keywords.
    
        Parameters:
            self -> Blacklist, whitelist and entities are taken at constuctor.

        Returns:
            List[Union[stix2.v21._DomainObject, stix2.v21._RelationshipObject]]: The list of the entities that are validated(remained) with the process.
        """
        list_result = []

        for entity in self.entities:
            entity_name = entity['name']

            #CVE's should be present as it is. So, firstly CVE's are extracted (and accepted as is)
            is_cve = self.__is_cve(entity_name) 
            if is_cve:
                list_result.append(entity)
                continue
            

            #Secondly, entities is searched in whitelist.
            found_in_whitelist = self.__search_in_whitelist(entity_name)
            if found_in_whitelist: 
                list_result.append(entity) #Found -> Accept
                continue


            #Not found in whitelist-> Search in blacklist
            #If it is not found in whitelist, entity is searched in blacklist.
            found_in_blacklist = self.__search_in_blacklist(entity_name)
            if found_in_blacklist:
                continue #Found -> Reject


            #Not found -> Process the entity.
            #If it is not found either on whitelist and blacklist, process the entity.

            #If there is a path part in the entity name, before the "processing" is done, we will search the path.
            #Path will be found just splitting its name from the <space> characters, while "processing" is done with splitting nearly all punctuation marks)
            entity_name_without_path = self.__extract_path_from_name(entity_name)

            #Process the entity.
            entity_name_updated = self.__process_entity(entity_name_without_path)
            entity_current = entity.new_version(name=entity_name_updated)
            
            #If there is a change in entity name after the process, search the new name in whitelist and blacklist again.
            if (entity_name_updated != entity_name) and (len(entity_name_updated) > 0): #if the updated entity nameis not empty string
            #Entity name changed. Again search in whitelist and blacklist respectively.
                found_in_whitelist = self.__search_in_whitelist(entity_name_updated)
                if found_in_whitelist:
                    list_result.append(entity_current) #Found -> Accept
                    continue

                #Not found in whitelist-> Search in blacklist
                #If it is not found in whitelist, entity is searched in blacklist.
                found_in_blacklist = self.__search_in_blacklist(entity_name_updated)
                if found_in_blacklist:
                    continue #Found -> Reject


            #If the entity is not found until here, look at the type of it and search the original entity(no name changes) in other types.
            #(maybe its type is written wrong. check it)
            entity_current_type_checked = self.__arrange_entity_type(entity_current)

            #b = entity_current['name']

            if entity_current_type_checked != None:
                list_result.append(entity_current_type_checked)
            else:
                if entity_name_updated != "": #if entity is not consist of just blacklist keywords (it is not empty after the processing):
                    #TODO
                    #set confidence to 0 and accept the data as it is.
                    #entity_updated_confidence = self.__change_confidence(entity, 0)
                    list_result.append(entity_current)

        # for label in self.created_labels: #add all of the created labels to the entity bundle
        #     list_result.append(label)
        #NOTE: Labels are not STIX objects so they cannot be added to the bundle, their ids are added in the object's labels field.

        return list_result
