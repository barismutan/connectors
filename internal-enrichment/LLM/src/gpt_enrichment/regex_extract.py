import re


class RegexExtractor:
    def __init__(self):
        super().__init__()
        
    def extract_ips(self,text):
        pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        ips = re.findall(pattern, text)
        return list(set(ips))

    def extract_urls(self,text):
        pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w.-]*"
        urls = re.findall(pattern, text)
        # if the last character is a dot, remove it
        urls = [url[:-1] if url[-1] == "." else url for url in urls]
        return list(set(urls))

    def extract_emails(self,text):
        pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
        emails = re.findall(pattern, text)
        return list(set(emails))

    def extract_sha_256s(self,text):
        pattern = r"[A-Fa-f0-9]{64}"
        sha_256s = re.findall(pattern, text)
        return list(set(sha_256s))

    def extract_sha_1s(self,text):
        pattern = r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])"
        sha_1s = re.findall(pattern, text)
        return list(set(sha_1s))

    def extract_md5s(self,text):
        pattern = r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"
        md5s = re.findall(pattern, text)
        return list(set(md5s))

    def extract_mitre_attack(self,text):
        pattern = r"(T[0-9]{4}(\.\d\d\d)?)"
        mitre_attacks = re.findall(pattern, text)
        # return [mitre_attack[0] for mitre_attack in mitre_attacks]
        return list(set([mitre_attack[0] for mitre_attack in mitre_attacks]))

    def extract_cve(self,text):
        pattern = r"CVE-[0-9]{4}-[0-9]{4,7}"
        cves = re.findall(pattern, text)
        return list(set(cves))

    def extract_cwe(self,text):
        pattern = r"CWE-[0-9]{1,4}"
        cwes = re.findall(pattern, text)
        return list(set(cwes))

    def extract_files(self,text):
        pattern = r"([a-zA-Z0-9_\\.\-\(\):]+\.(exe|dll|py|js|docx|doc|xls|xlsx|ppt|pptx|pdf|txt|rtf|zip|rar|tar|gz|7z|bin|sh|php|html|htm|xml|json|csv|tsv|ps1|bat|vbs|java|class|apk|ipa|iso|i))"
        files = re.findall(pattern, text)
        return list(set([file[0] for file in files]))

    def extract_all(self,text : str) -> dict:
        sha256_matches= self.extract_sha_256s(text)  
        sha1_matches = self.extract_sha_1s(text)
        md5_matches = self.extract_md5s(text)
        
        #if an element is found as a substring of another element, remove it  
        sha1_matches = [m for m in sha1_matches if not any(m in x for x in sha256_matches)]
        md5_matches = [m for m in md5_matches if not any(m in x for x in sha256_matches) and not any(m in x for x in sha1_matches)]

        #unique all lists
        sha1_matches = list(set(sha1_matches))
        sha256_matches = list(set(sha256_matches))
        md5_matches = list(set(md5_matches))
        return { #TODO: implement logic here that checks whether smaller hashes are contained in larger hashes
            "ips": self.extract_ips(text),
            "urls": self.extract_urls(text),
            "emails": self.extract_emails(text),
            "sha256s": sha256_matches,
            "sha1s": sha1_matches,
            "md5s": md5_matches,
            "mitre_attacks": self.extract_mitre_attack(text),
            "cves": self.extract_cve(text),
            "cwes": self.extract_cwe(text),
            "files": self.extract_files(text)
        }