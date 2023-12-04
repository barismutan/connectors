from pydantic import BaseModel, constr,StringConstraints, validator,root_validator,model_validator
from typing import List,Union,Literal,Annotated
import json

class VictimOrganizationModel(BaseModel):
    name: str

class VictimCountryModel(BaseModel):
    name: str

class VictimSectorModel(BaseModel):
    name: str

class VictimRegionModel(BaseModel):
    name: str


class IntrusionSetModel(BaseModel):
    name: str


class MalwareModel(BaseModel):
    name: str
    type: Literal["keylogger","backdoor","downloader","dropper","rat","rootkit","botnet","ransomware","adware","spyware","worm","wiper","cryptojacker","cryptominer","infostealer","mobile_malware","browser_hijacker"]

class ToolsModel(BaseModel):
    name: str


class AttackPatternModel(BaseModel):
    name: str
    id: Annotated[str,StringConstraints(pattern=r'T\d{4}(\.\d{3})?')]
    


class VulnerabilityModel(BaseModel):
    name: Annotated[str,StringConstraints(pattern=r'CVE-\d{4}-\d{4,7}')]

class IndicatorModel(BaseModel):
    type: Annotated[str,StringConstraints(pattern=r'file:hashes\.(MD5|SHA-1|SHA-256)')] #TODO: use stix validator instead
    value:Annotated[str,StringConstraints(pattern=r'[a-fA-F\d]{32}|[a-fA-F\d]{40}|[a-fA-F\d]{64}')]
    
    @root_validator(pre=True)
    def check_type_value_match(cls, values):
        v_type = values.get('type')
        v_value = values.get('value')

        if v_type.startswith('file:hashes.MD5') and len(v_value) != 32:
            raise ValueError('MD5 hash must be 32 characters long')
        elif v_type.startswith('file:hashes.SHA-1') and len(v_value) != 40:
            raise ValueError('SHA-1 hash must be 40 characters long')
        elif v_type.startswith('file:hashes.SHA-256') and len(v_value) != 64:
            raise ValueError('SHA-256 hash must be 64 characters long')

        return values
    


class LLMResponseModel(BaseModel):
    title: str
    victim_organization: str
    victim_countries: List[str]
    victim_industries: List[str]
    victim_regions: List[str]
    intrusion_sets: List[str]
    malware: List[MalwareModel]
    tools: List[str]
    attack_patterns: List[AttackPatternModel]
    vulnerabilities: List[Annotated[str,StringConstraints(pattern=r'CVE-\d{4}-\d{4,7}')]]
    indicators: List[IndicatorModel]  

    