import sys
import os
import yaml
import stix2
import json
from datetime import datetime
from pycti import OpenCTIConnectorHelper, Note, get_config_variable
from .preprocessor import Preprocessor
from .postprocessor import Postprocessor
from .prompter import GptClient
from .blog_fetcher import BlogFetcher
from .regex_extract import RegexExtractor
from threading import Lock
from gpt_enrichment.utils import *


class GptEnrichmentConnector:
    def __init__(self):
        self._SOURCE_NAME = "GPT Enrichment Connector"
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        

        self.helper = OpenCTIConnectorHelper(config)
        self.temperature = get_config_variable(
            "GPT_ENRICHMENT_TEMPERATURE", ["gpt_enrichment", "temperature"], config, False, 0.0
        ) # Deprecated
        self.model = get_config_variable(
            "GPT_ENRICHMENT_MODEL", ["gpt_enrichment", "model"], config, False, "gpt-3.5-turbo-16k"
        ) # Deprecated
        self.apikey = get_config_variable(
            "GPT_ENRICHMENT_APIKEY", ["gpt_enrichment", "apikey"], config, False, ""
        ) # Deprecated

        self.author = self.helper.api.identity.create(type="Organization", name=self._SOURCE_NAME, description="GPT-Enrichment Connector", confidence=self.helper.connect_confidence_level)['standard_id']

        self.prompt_version = get_config_variable(
            "GPT_ENRICHMENT_PROMPT_VERSION", ["gpt_enrichment", "prompt_version"], config, False, "v0.0.1"
        ) # Deprecated
        self.update_existing = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA", ["connector", "update_existing_data"], config, False, False
        )#TODO: add this to config file

        api_getaway_url=get_config_variable(
            "GPT_ENRICHMENT_API_GETAWAY_URL", ["gpt_enrichment", "api_getaway_url"], config, False, ""
        ) #NEW

        queue_url=get_config_variable(
            "GPT_ENRICHMENT_QUEUE_URL", ["gpt_enrichment", "queue_url"], config, False, ""
        ) #NEW

        self.llm_client= GptClient(api_getaway_url,queue_url)

        self.fetcher= BlogFetcher()


        self.colors={
            "GREEN":"00FF00",
            "RED":"FF0000",
            "YELLOW":"FFFF00"
        }

        self.connector_dockerized=get_config_variable(
            "CONNECTOR_DOCKERIZED", ["connector", "dockerized"], config, False, False
        )

        self.use_test_prompt=get_config_variable(
            "GPT_ENRICHMENT_USE_TEST_PROMPT", ["gpt_enrichment", "use_test_prompt"], config, False, False
        )
        
        self.duplicate_report=get_config_variable(
            "GPT_ENRICHMENT_DUPLICATE_REPORT", ["gpt_enrichment", "duplicate_report"], config, False, False
        )
            



        self.lock = Lock()
        self.preprocessor= Preprocessor(self.helper)
        self.postprocessor= Postprocessor(self.helper)
        

        

        if not self.connector_dockerized:
            self.helper.connector_config['connection']['host']='localhost'
        

        

        

        
        self.regex_extractor=RegexExtractor()


    def run(self):
        # Start the main loop of the connector
        self.helper.listen(self.start_enrichment)
    
    ##these are the builder functions to extract entities, better to move to a different file later
    
    def build_malwares(self, blog : dict) -> list[stix2.Malware]:
        malware_entities = []
        for m in blog['malware']:
            name=m['name']
            types=m['types']
            self.helper.log_debug(f"TYPE of self.author: {type(self.author)}")
            self.helper.log_debug(f"self.author: {str(self.author)}")
            malware_entities.append(create_malware(m['name'],self.author,0,[],malware_types=types))
        return malware_entities

    def build_regions(self, blog : dict) -> list[stix2.Location]: #TODO: split this into create_country and create_region
        region_entities = []
        for r in blog['victim_region']:
            region_entities.append(create_region(r,self.author)) #TODO: in utils only create_country is availale rn, later need to implement and change to create_region.
        return region_entities
    
    def build_countries(self, blog : dict) -> list[stix2.Location]:
        country_entities = []
        for c in blog['victim_country']:
            country_entities.append(create_country(c,self.author))
        return country_entities


    def build_victims(self, blog : dict) -> list[stix2.Identity]:
        # return [] #TODO: add this
        # victim_entities = []
        # for v in blog['victims']:
        #     victim_entities.append(create_organization(v,self.author)) #TODO:not sure about this.
        # return victim_entities
        if blog['victim_organization'] == "": #checking against no victim found case
            return []
        victim=create_organization(blog['victim_organization'],self.author)
        

        return [victim]
        
        

    def build_industries(self, blog : dict) -> list[stix2.Identity]: 
        industry_entities = []
        for i in blog['sectors']:
            industry_entities.append(create_sector(i,self.author))
        return industry_entities


    def build_attack_patterns(self, blog : dict) -> list[stix2.AttackPattern]:
        attack_pattern_entities = []
        for ap in blog['attack_patterns']:
            name=ap['name']
            tid=ap['id']#NOTE: this could be useless (it is the mitre id.)
            attack_pattern_entities.append(create_attack_pattern(name,self.author,0,[],[]))
        return attack_pattern_entities
        
        


    def build_intrusion_sets(self, blog : dict) -> list[stix2.IntrusionSet]:
        intrusion_set_entities = []
        actor_motivations=blog['actor_motivation']
        for iset in blog['intrusion_sets']:
            name=iset['name']
            aliases=iset['aliases']
            intrusion_set_entities.append(create_intrusion_set(name,self.author,0,[],aliases=aliases,secondary_motivations=actor_motivations))
        return intrusion_set_entities
    
    #TODO: add Report.

    def build_vulnerabilities(self, blog : dict) -> list[stix2.Vulnerability]:
        vulnerability_entities = []
        for v in blog['vulnerabilities']:
            vulnerability_entities.append(create_vulnerability(v,self.author,0,[],[]))
        return vulnerability_entities
    
    def build_tools(self, blog : dict) -> list[stix2.Tool]:
        tool_entities = []
        for t in blog['tools']:
            tool_entities.append(create_tool(t,self.author,0,[],[]))
        return tool_entities
    
    # def build_softwares(self, blog : dict) -> list[stix2.Software]:
    #     software_entities = []
    #     for s in blog['software']:
    #         name=s['name']
    #         for v in s['versions']:
    #             software_entities.append(create_software(name,self.author,0,[],v))
    
    def build_file_observables(self, blog : dict) -> list[stix2.File|stix2.Indicator]:
        objects=[]
        all_hashes=[]
        all_hashes.extend([("md5",md5) for md5 in blog['observables']['md5s']])
        all_hashes.extend([("sha1",sha1) for sha1 in blog['observables']['sha1s']])
        all_hashes.extend([("sha256",sha256) for sha256 in blog['observables']['sha256s']])
        author_identity=self.helper.api.identity.read(filters=[{'key':'name','values':[self._SOURCE_NAME]}])
        for hash_type,hash_value in all_hashes:
            
            factory=OBSERVATION_FACTORY_FILE_MD5 if hash_type=="md5" else OBSERVATION_FACTORY_FILE_SHA1 if hash_type=="sha1" else OBSERVATION_FACTORY_FILE_SHA256
            

            

            observable_properties= ObservableProperties(
                value=hash_value,
                created_by=author_identity,
                labels=[],
                object_markings=[]
            )
            observable=factory.create_observable(observable_properties)
            objects.append(observable)
            pattern=factory.create_indicator_pattern(hash_value)
            

            indicator=create_indicator(
                pattern.pattern,
                "stix",
                self.author,
                hash_value,
                0
            )
            objects.append(indicator)
            relationship=create_relationship(
                "based-on",
                self.author,
                indicator,
                observable,
                0,
                []
            )
            objects.append(relationship)
        return objects
                   


    def build_reports(self, entities : list) -> list[stix2.Report]:

        pass#TODO: this is kinda garbage here. actually needed for the import connector.





    ## ----------------- ## TODO: add external references to all objects (entites, relationships etc.)

    ##these are the relationship builder functions , better to move to a different file later

    def build_malware_region_relationships(self, malwares,regions) -> list[stix2.Relationship]:

        return create_relationships(
            "targets",
            self.author,
            malwares,
            regions,
            0,
            []

        )
    
    def build_malware_country_relationships(self, malwares,countries) -> list[stix2.Relationship]:
            
            return create_relationships(
                "targets",
                self.author,
                malwares,
                countries,
                0,
                []
            )

    def build_malware_victim_relationships(self, malwares,victims ) -> list[stix2.Relationship]:
        

        

        return create_relationships(
            "targets",
            self.author,
            malwares,
            victims,
            0,
            []
        )

    def build_malware_industry_relationships(self, malwares,industries ) -> list[stix2.Relationship]:

        return create_relationships(
            "targets",
            self.author,
            malwares,
            industries,
            0,
            []
        )
    

    def build_malware_attack_pattern_relationships(self, malwares,attack_patterns) -> list[stix2.Relationship]:

        return create_relationships(
            "uses",
            self.author,
            malwares,
            attack_patterns,
            0,
            []
        )
    

    def build_malware_intrusion_set_relationships(self,  malwares,intrusion_sets) -> list[stix2.Relationship]:

        return create_relationships(
            "uses",
            self.author,
            intrusion_sets,
            malwares,
            0,
            []
        )
    
    def build_tool_intrusion_set_relationships(self,  tools,intrusion_sets) -> list[stix2.Relationship]:
            
            return create_relationships(
                "uses",
                self.author,
                intrusion_sets,
                tools,
                0,
                []
            )


    def build_region_victim_relationships(self, regions,victims) -> list[stix2.Relationship]:

        return create_relationships(
            "located-at",
            self.author,
            victims,
            regions,
            0,
            []
        )
    
    def build_country_victim_relationships(self, countries,victims) -> list[stix2.Relationship]:
         
            return create_relationships(
                "located-at",
                self.author,
                victims,
                countries,
                0,
                []
            )


    # def build_region_industry(self, blog : dict) -> list: # This is dumb.
    #     pass

    def build_region_attack_pattern_relationships(self, regions,attack_patterns) -> list[stix2.Relationship]:

        return create_relationships(
            "targets",
            self.author,
            attack_patterns,
            regions,
            0,
            []
        )
    
    def build_country_attack_pattern_relationships(self, countries,attack_patterns) -> list[stix2.Relationship]:
                
                return create_relationships(
                    "targets",
                    self.author,
                    attack_patterns,
                    countries,
                    0,
                    []
                )
    


    def build_region_intrusion_set_relationships(self, regions,intrusion_sets) -> list[stix2.Relationship]:

        return create_relationships(
            "targets",
            self.author,
            intrusion_sets,
            regions,
            0,
            []
        )
    
    def build_country_intrusion_set_relationships(self, countries,intrusion_sets) -> list[stix2.Relationship]:
                    
                    return create_relationships(
                        "targets",
                        self.author,
                        intrusion_sets,
                        countries,
                        0,
                        []
                    )

    def build_victim_industry_relationships(self, victims,industries) -> list[stix2.Relationship]:
        return create_relationships(
            "related-to",
            self.author,
            industries,
            victims,
            0,
            []
        )



    def build_victim_attack_pattern_relationships(self, victims,attack_patterns) -> list[stix2.Relationship]:

        return create_relationships(
            "targets", #TODO: I am not sure about this relationship type.
            self.author,
            attack_patterns,
            victims,
            0,
            []
        )


    def build_victim_intrusion_set_relationships(self, victims,intrusion_sets) -> list[stix2.Relationship]:

        return create_relationships(
            "targets",
            self.author,
            intrusion_sets,
            victims,
            0,
            []
        )

    def build_industry_attack_pattern_relationships(self, industries,attack_patterns) -> list[stix2.Relationship]:

        return create_relationships(
            "targets",
            self.author,
            attack_patterns,
            industries,
            0,
            []
        )


    def build_industry_intrusion_set_relationships(self, industries,intrusion_sets) -> list[stix2.Relationship]:

        return create_relationships(
            "targets",
            self.author,
            intrusion_sets,
            industries,
            0,
            []
        )


    def build_attack_pattern_intrusion_set_relationships(self, attack_patterns,intrusion_sets) -> list[stix2.Relationship]:

        return create_relationships(
            "uses",
            self.author,
            intrusion_sets,
            attack_patterns,
            0,
            []
        )
    
    def build_malware_vulnerability_relationships(self, malwares,vulnerabilities) -> list[stix2.Relationship]:
            
            return create_relationships(
                "exploits",
                self.author,
                malwares,
                vulnerabilities,
                0,
                []
            )


    def build_intrusion_set_vulnerability_relationships(self, intrusion_sets,vulnerabilities) -> list[stix2.Relationship]:
            
            return create_relationships(
                "targets",
                self.author,
                intrusion_sets,
                vulnerabilities,
                0,
                get_tlp_string_marking_definition("white") #experimenting with this.
            )
    
    def build_intrusion_set_organization_relationships(self, intrusion_sets,organizations) -> list[stix2.Relationship]:
                
                return create_relationships(
                    "targets",
                    self.author,
                    intrusion_sets,
                    organizations,
                    0,
                    []
                )
    
    def build_victim_malware_relationships(self, victims,malwares) -> list[stix2.Relationship]:
            return create_relationships(
                "targets",
                self.author,
                malwares,
                victims,
                0,
                []
            )
    
    def build_victim_vulnerability_relationships(self, victims,vulnerabilities) -> list[stix2.Relationship]:
            return create_relationships(
                "related-to",
                self.author,
                vulnerabilities,
                victims,
                0,
                []
            )
    
    # def build_software_vulnerability_relationships(self, softwares,vulnerabilities) -> list[stix2.Relationship]:
    #         return create_relationships(
    #             "targets",
    #             self.author,
    #             softwares,
    #             vulnerabilities,
    #             0,
    #             []
    #         )



    ## ----------------- ##

    def build_entities(self, blog : dict) -> list: #TODO: add type in annotation
        malware_entites = self.build_malwares(blog)
        region_entities = self.build_regions(blog)
        country_entities= self.build_countries(blog)
        victim_entities = self.build_victims(blog)
        industry_entities = self.build_industries(blog)
        attack_pattern_entities = self.build_attack_patterns(blog)
        vulnerability_entities = self.build_vulnerabilities(blog)
        intrusion_set_entities = self.build_intrusion_sets(blog)
        # software_entities = self.build_softwares(blog)
        return {
            "malware": malware_entites,
            "regions": region_entities,
            "countries": country_entities,
            "victims": victim_entities,
            "sectors": industry_entities,
            "attack_patterns": attack_pattern_entities,
            "intrusion_sets": intrusion_set_entities,
            "vulnerabilities": vulnerability_entities,
            # "software": software_entities
        }

    def build_relationships(self,entities, previous_entities,connect_previous_entities=False) -> list[stix2.Relationship]: #TODO: add attack pattern relationships
        #TODO: rename all variables to match STIX object types.
        #TODO: add Intrusion Set- Vulnerability relationship
        #TODO: add Organization- Sector relationship
        if connect_previous_entities: #TODO
            pass
        else:
            pass
        malware_region_relationships = self.build_malware_region_relationships(entities["malware"],entities["regions"])#split to create_malware_region_relationships and create_malware_country_relationships
        malware_country_relationships = self.build_malware_country_relationships(entities["malware"],entities["countries"])
        malware_victim_relationships = self.build_malware_victim_relationships(entities["malware"],entities["victims"])
        malware_industry_relationships = self.build_malware_industry_relationships(entities["malware"],entities["sectors"])
        malware_attack_pattern_relationships = self.build_malware_attack_pattern_relationships(entities["malware"],entities["attack_patterns"])
        malware_intrusion_set_relationships = self.build_malware_intrusion_set_relationships(entities["malware"],entities["intrusion_sets"])
        region_victim_relationships = self.build_region_victim_relationships(entities["regions"],entities["victims"])
        country_victim_relationships = self.build_country_victim_relationships(entities["countries"],entities["victims"])
        region_attack_pattern_relationships = self.build_region_attack_pattern_relationships(entities["regions"],entities["attack_patterns"])
        country_attack_pattern_relationships = self.build_country_attack_pattern_relationships(entities["countries"],entities["attack_patterns"])
        region_intrusion_set_relationships = self.build_region_intrusion_set_relationships(entities["regions"],entities["intrusion_sets"])
        country_intrusion_set_relationships = self.build_country_intrusion_set_relationships(entities["countries"],entities["intrusion_sets"])
        victim_industry_relationships = self.build_victim_industry_relationships(entities["victims"],entities["sectors"])
        victim_attack_pattern_relationships = self.build_victim_attack_pattern_relationships(entities["victims"],entities["attack_patterns"])
        victim_intrusion_set_relationships = self.build_victim_intrusion_set_relationships(entities["victims"],entities["intrusion_sets"])
        industry_attack_pattern_relationships = self.build_industry_attack_pattern_relationships(entities["sectors"],entities["attack_patterns"])
        industry_intrusion_set_relationships = self.build_industry_intrusion_set_relationships(entities["sectors"],entities["intrusion_sets"])
        attack_pattern_intrusion_set_relationships = self.build_attack_pattern_intrusion_set_relationships(entities["attack_patterns"],entities["intrusion_sets"])
        malware_vulnerability_relationships = self.build_malware_vulnerability_relationships(entities["malware"],entities["vulnerabilities"])
        victim_sector_relationships = self.build_victim_industry_relationships(entities["victims"],entities["sectors"])
        intrusion_set_vulnerability_relationships = self.build_intrusion_set_vulnerability_relationships(entities["intrusion_sets"],entities["vulnerabilities"])
        intrusion_set_victim_relationships = self.build_intrusion_set_organization_relationships(entities["intrusion_sets"],entities["victims"])
        victim_malware_relationships = self.build_victim_malware_relationships(entities["victims"],entities["malware"])
        victim_vulnerability_relationships = self.build_victim_vulnerability_relationships(entities["victims"],entities["vulnerabilities"])
        # software_vulnerability_relationships = self.build_software_vulnerability_relationships(entities["software"],entities["vulnerabilities"])
        #To add: vulnerability-software relationship
        return {
            "malware_region": malware_region_relationships,
            "malware_country": malware_country_relationships,
            "malware_victim": malware_victim_relationships,
            "malware_industry": malware_industry_relationships,
            "malware_attack_pattern": malware_attack_pattern_relationships,
            "malware_intrusion_set": malware_intrusion_set_relationships,
            "malware_vulnerability": malware_vulnerability_relationships,
            "region_victim": region_victim_relationships,
            "country_victim": country_victim_relationships,
            # "region_industry": region_industry_relationships,
            "region_attack_pattern": region_attack_pattern_relationships,
            "country_attack_pattern": country_attack_pattern_relationships,
            "region_intrusion_set": region_intrusion_set_relationships,
            "country_intrusion_set": country_intrusion_set_relationships,
            "victim_industry": victim_industry_relationships,
            "victim_attack_pattern": victim_attack_pattern_relationships,
            "victim_intrusion_set": victim_intrusion_set_relationships,
            "industry_attack_pattern": industry_attack_pattern_relationships,
            "industry_intrusion_set": industry_intrusion_set_relationships,
            "attack_pattern_intrusion_set": attack_pattern_intrusion_set_relationships,
            "victim_sector": victim_sector_relationships,
            "intrusion_set_vulnerability": intrusion_set_vulnerability_relationships,
            "intrusion_set_organization": intrusion_set_victim_relationships,
            "victim_malware": victim_malware_relationships,
            "victim_vulnerability": victim_vulnerability_relationships,
            # "software_vulnerability": software_vulnerability_relationships

        }
        
    def build_observables(self, blog : dict) -> list[stix2.Indicator]:
        file_observables=self.build_file_observables(blog)
        #...
        return {
            "file_observables":file_observables
        }
    

    
    def fetch_current_entities(self, report:stix2.Report) -> list: #TODO: add type in annotation

        pass


    def build_stix_bundle(self, entities:dict,relationships:dict,observables:dict) -> stix2.Bundle: #TODO: build function in builder.py in AV connector is pretty good, later we can use that.
        # self.helper.log_info(f"Bundling {len(entities)} entities and {len(relationships)}")
        

        

        

        

        num_entities = len([entity_package for entity_package in entities.values()]) #TODO:this doesnt work, need to fix.
        num_relationships = len([relationship_package for relationship_package in relationships.values()])
        self.helper.log_info(f"Bundling {num_entities} entities and {num_relationships} relationships")
        entities_list = list(entities.values())
        relationships_list = list(relationships.values())
        observables_list = observables
        object_refs=create_object_refs(
            entities_list,
            relationships_list,
            observables_list
        )
        all_entities=[] #TODO: RENAME TO all_objects

        all_entities.extend(object_refs)  #Here the order may be important, not sure.
        all_entities.extend(entities_list)
        all_entities.extend(relationships_list)
        all_entities.extend([observables_list[observable_type] for observable_type in observables_list.keys()])
        
        

        
        all_entities_unpacked=[]
        for entity in all_entities:
            self.helper.log_debug(f"DEBUG DEBUG: Entity: {entity}")
            if type(entity)==list:
                all_entities_unpacked.extend(entity)

        
        
        self.helper.log_debug(f"DEBUG DEBUG: All entities: {all_entities}")
        
        

        
        return stix2.Bundle(
            objects=all_entities_unpacked,
            allow_custom=True,
        )
    
    def send_bundle(self, bundle : stix2.Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.log_info(f"Sending bundle: {serialized_bundle}")
        friendly_name="Running GPT-Enrichment Connector @{}".format(datetime.now().isoformat())
        work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )#TODO: we could include the prompt here.
        self.helper.send_stix2_bundle(serialized_bundle,update=self.update_existing,work_id=work_id)
        



    ##Labelling process of the objects
    def create_label(self,tag:str, color:str) -> None:#TODO: find the type for a tag
        self.helper.log_info(f"Creating label: {tag}")
        tag=self.helper.api.label.create(
             value=tag,
             color=color
        )
        return tag


    def label_report(self, report:stix2.Report,success:bool) -> None:
        labelling_success=False
        if success:
            self.helper.log_info(f"Labelling report: {report['id']} as successful enrichment.")
            label=self.create_label("gpt-enrichment-success",self.colors["GREEN"])
            labelling_success=self.helper.api.stix_domain_object.add_label(id=report['id'],label_id=label['id']) #it might be the case that this is a core object
        else:
            self.helper.log_info(f"Labelling report: {report['id']} as failed enrichment.")
            label=self.create_label("gpt-enrichment-failed",self.colors["RED"])
            labelling_success=self.helper.api.stix_domain_object.add_label(id=report['id'],label_id=label['id'])
        
        if labelling_success:
            self.helper.log_info(f"Successfully labelled report: {report['id']}")
        else:
            self.helper.log_error(f"Failed to label report: {report['id']}")

        return
    
 
    def label_entity(self, entity:stix2.v21._DomainObject) -> None:
         pass
    
    def label_relationship(self, relationship:stix2.v21._RelationshipObject,) -> None:
         pass
    
    def label_entities(self,entities:list[stix2.v21._DomainObject]) -> None:
        pass

    def label_relationships(self,relationships:list[stix2.v21._RelationshipObject]) -> None:
        pass

    ## ----------------- ##
    
    ##Report duplication function
    def create_bundle_with_new_report(self,old_report,entities:dict[str,stix2.v21._DomainObject],relationships:dict[str,stix2.Relationship],observables:dict[str,stix2.v21._Observable|stix2.v21.Indicator]) -> None:
        

        entities_unpacked=[entity for entity in entities.values() for entity in entity]
        

        relationships_unpacked=[relationship for relationship in relationships.values() for relationship in relationship]
        observables_unpacked=[observable for observable in observables.values() for observable in observable]
        new_report=create_report(
            "LLM Generated-- "+old_report['name'],
            old_report['published'],
            objects=create_object_refs(
                entities_unpacked,
                relationships_unpacked,
                observables_unpacked
            )
        )
        entities['reports']=[new_report]
        
        new_bundle=self.build_stix_bundle(entities,relationships,observables)
        return new_bundle
        
    
    def update_report_objects(self,stix_bundle,report_id) -> None:
        for object in stix_bundle['objects']:
            try:
                self.helper.log_debug(f"DEBUG DEBUG: Object: {object}, Type of object: {type(object)}")
                self.helper.api.report.add_stix_object_or_stix_relationship(id=report_id, stixObjectOrStixRelationshipId=object["id"]) #TODO: this line throws "MissingReferenceError" every first run, fix later
            except Exception as e:
                self.helper.log_debug(f"DEBUG DEBUG: Exception: {e}")
                continue
    

        
    def start_enrichment(self, data):
        self.lock.acquire(blocking=True)
        entity_id = data["entity_id"]
        # print(json.dumps(
        #      data, indent=4
        #      )
        #     )
        report = self.helper.api.report.read(id=entity_id)
        if report is None:
            raise ValueError("Report not found")
        
        try:
            for external_reference in report["externalReferences"]:
                if external_reference["url"].startswith("https://otx.alienvault"):
                    continue
                # self.helper.api.work.to_received()
                blog_html = self.fetcher.get_html(self.helper, external_reference["url"])


                blog = self.preprocessor.preprocess(blog_html)
                

                #deneme
                # gpt_response = self.llm_client.prompt(self.helper, entity_id,blog,test_mode=self.use_test_prompt)
                # gpt_response_postprocessed = self.postprocessor.postprocess(gpt_response)
                # note_body = f"Temperature: {self.temperature}\nModel: {self.model}\nPrompt: {self.prompt_version}\n```\n" + json.dumps(gpt_response_postprocessed,indent=4) + "\n```"
                
                
                ##-----------------## Extract entities, relationships and build stix bundle
                self.helper.log_debug(f"Blog (after preprocessing): {blog}")
                # entities = self.build_entities(gpt_response_postprocessed)
                entities={}
                # self.helper.log_debug(f"Entities: {entities}")
                # relationships = self.build_relationships(entities, gpt_response_postprocessed)
                relationships={}
                # self.helper.log_debug(f"Relationships: {relationships}")
                gpt_response_postprocessed={
                    "observables": self.regex_extractor.extract_all(blog)
                }
                observables = self.build_observables(gpt_response_postprocessed)
                
                #NOTE:Uncomment above part later
                

                self.helper.log_debug(f"Observables: {observables}")
                

                ##-----------------##

                #Send the bundle to OpenCTI
                # test=self.build_stix_bundle(entities,relationships)
                

                
                if self.duplicate_report:
                    bundle_with_new_report=self.create_bundle_with_new_report(report,entities,relationships,observables)#TODO  
                    self.send_bundle(bundle_with_new_report)
                else:
                    stix_bundle = self.build_stix_bundle(entities,relationships,observables)
                    self.send_bundle(stix_bundle)
                    self.update_report_objects(stix_bundle,report['id'])



                # self.helper.api.note.create(
                #             id=Note.generate_id(datetime.datetime.now().isoformat(), note_body),
                #             abstract="GPT-Enrichment Result",
                #             content=note_body,
                #             created_by_ref=self.author,
                #             objects=[entity_id],
                #         )
                # self.helper.log_info("Created a gpt enrichment note for external reference: " + external_reference["url"])

                # blog_only_p = self.preprocessor.extract_p_text(blog_html)
                # regex_extract = RegexExtractor.extract_all(blog_only_p)

                # note_body_regex = f"```Regex Extractor: \n" + json.dumps(regex_extract, indent=2) + "\n```"

                # self.helper.api.note.create(
                #             id=Note.generate_id(datetime.datetime.now().isoformat(), note_body_regex),
                #             abstract="Regex Extractor Result",
                #             content=note_body_regex,
                #             created_by_ref=self.author,
                #             objects=[entity_id],
                #         )
                # self.helper.log_info("Created a regex extractor note for external reference: " + external_reference["url"])
            
            self.label_report(report,True)
            self.lock.release()
            return "Sent {} entities and {} relationships for worker import.".format(len(entities), len(relationships))
        except Exception as e:
            self.label_report(report,False)
            self.lock.release()
            raise ValueError("Error during enrichment: " + str(e))

    
#TODO: Add Vulnerability,Attack Pattern, Indicator info.
#TODO: add indicator indicates intrusion-set info

    