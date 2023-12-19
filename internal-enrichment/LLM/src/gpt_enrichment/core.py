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
from .builder import ResponseBundleBuilder


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
        
        self.create_malware_indicator_relationships=get_config_variable(
            "GPT_ENRICHMENT_CREATE_MALWARE_INDICATOR_RELATIONSHIPS", ["gpt_enrichment", "create_malware_indicator_relationships"], config, False, False
        ) #This will only be used to create relationships between malware and indicators iff only 1 malware is found in the blog.
        
        
            



        self.lock = Lock()
        self.preprocessor= Preprocessor(self.helper)
        self.postprocessor= Postprocessor(self.helper)
        

        

        if not self.connector_dockerized:
            self.helper.connector_config['connection']['host']='localhost'
        

        

        

        
        self.regex_extractor=RegexExtractor()


    def run(self):
        # Start the main loop of the connector
        self.helper.listen(self.start_enrichment)
    
    

    
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

        report = self.helper.api.report.read(id=entity_id)
        print("Report: {}".format(report))
        print("Type of report: {}".format(type(report)))
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
                gpt_response = self.llm_client.prompt(self.helper, entity_id,blog,test_mode=self.use_test_prompt)
                gpt_response_postprocessed = self.postprocessor.postprocess(gpt_response)
                
                ##-----------------## Extract entities, relationships and build stix bundle
                self.helper.log_debug(f"Blog (after preprocessing): {blog}")


                gpt_response_postprocessed['observables']=self.regex_extractor.extract_all(blog)
                author_identity=self.helper.api.identity.read(filters=[{'key':'name','values':[self._SOURCE_NAME]}])
                
                
                builder=ResponseBundleBuilder(
                    llm_response=gpt_response_postprocessed,
                    author=self.author,
                    report=report,
                    external_references=[external_reference],
                    duplicate_report=self.duplicate_report,
                    object_markings=[],
                    confidence=0,
                    author_identity=author_identity,
                )
                bundle=builder.build()
                self.send_bundle(bundle)

            
            self.label_report(report,True)
            self.lock.release()
            return "Sent bundle successfully"
        except Exception as e:
            self.label_report(report,False)
            self.lock.release()
            raise ValueError("Error during enrichment: " + str(e))

    
#TODO: Add Vulnerability,Attack Pattern, Indicator info.
#TODO: add indicator indicates intrusion-set info

    