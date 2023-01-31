from pymongo.mongo_client import MongoClient
from dotenv import load_dotenv
from os import getenv
import wfAnalyzer
import wfExtractor
import argparse
import re
import json
from requests import get

client = MongoClient(getenv("srcDB"))
local = MongoClient('localhost')

db = client['git-reactions']['workflows']
results = local['ghast']['results']
ghast_chace = local['ghast']['cache']
tags_chace = local['ghast']['tags_chace']

TOKEN = getenv("ght")

def get_tags(repo):
    with MongoClient() as client:
        item = client['ghast']['repo_cache'].find_one({'repo' : repo})
        if item:
            return item['tags']
        api_url = "https://api.github.com/repos/" + repo + "/tags"
        req = get(api_url, headers={f"Authorization": "token {TOKEN}"})
        if req.status_code == 200:
            tags = json.loads(req.text)
            entry = {"repo" : repo, "tags" : tags}  
            client['ghast']['repo_cache'].insert_one(entry)
        if req.status_code != 200:
            wfAnalyzer.await_limit()
            return get_tags(repo)
    tags = json.loads(req.text)
    return tags

def analyze(dictwf, wfID, repo):
    commit_rex = r"[0-9a-f]{40}"
    vulns = {}
    for wf_file in dictwf:
        vulns.update({wf_file: {}})
        for wf in dictwf.get(wf_file):
            # print(wf)
            _runs = wfAnalyzer.getRuns(wf)
            _uses = wfAnalyzer.getOOD(wf)
            _perms = wfAnalyzer.getPerms(wf)
            if isinstance(wf.get('events'), dict):
                vulns[wf_file].update({wf.get('name'): {'events': (wf.get('events').get('type'), wf.get('events').get('security_rank')), "issues": []}})
            else:
                for e in wf.get('events'):
                    vulns[wf_file].update({wf.get('name'): {'events': (e.get('type'), e.get('security_rank')), "issues": []}})
                    
            if _runs != []:
                if _runs:
                    vulns[wf_file][wf.get('name')]['issues'].append(([i.name for i in wfAnalyzer.critical_gh_context if i.value in ''.join(_runs[0][0]['line'])], ''.join(_runs[0][0]['line'])))
                    vulns[wf_file][wf.get('name')]['issues'].append(([i.name for i in wfAnalyzer.critical_secrets if i.value in ''.join(_runs[0][0]['line'])], ''.join(_runs[0][0]['line'])))
            
            
            if len(_perms) > 0:
                wf_perms = False
                if _perms.get('wf') != 'None':
                    wf_perms = True
                for job_name, job_p in _perms.get('jobs').items():
                    if not job_p and wf_perms:
                        vulns[wf_file][wf.get('name')]['issues'].append((job_name, wfAnalyzer.critical_permissions.ONLY_WF_DECLARATION.value))
                    elif not job_p and not wf_perms:
                        vulns[wf_file][wf.get('name')]['issues'].append((job_name, wfAnalyzer.critical_permissions.NO_DECLARATION.value))
                        
            tags = get_tags(repo)
            if len(_uses) > 0:
                for ood in _uses:
                    if re.match(ood[1].split("@")[-1], commit_rex):
                        if not (ood[1].split("@")[-1] == tags[0].get('commit').get('sha')):
                            print("CASE")
                            vulns[wf_file][wf.get('name')]['issues'].append((ood[0], wfAnalyzer.critical_tp_workflow.WF_OOD.value))
                    elif not ood[2] and not re.match(ood[1].split("@")[-1], commit_rex):
                        vulns[wf_file][wf.get('name')]['issues'].append((ood[0], wfAnalyzer.critical_tp_workflow.WF_OOD.value))
                        vulns[wf_file][wf.get('name')]['issues'].append((ood[0], wfAnalyzer.critical_tp_workflow.NO_PINNING.value))
                    elif not ood[2] and re.match(ood[1].split("@")[-1], commit_rex):
                        vulns[wf_file][wf.get('name')]['issues'].append((ood[0], wfAnalyzer.critical_tp_workflow.WF_OOD.value))
                    elif not re.match(ood[1].split("@")[-1], commit_rex):
                        vulns[wf_file][wf.get('name')]['issues'].append((ood[0], wfAnalyzer.critical_tp_workflow.NO_PINNING.value))
    with MongoClient() as client:
        client['ghast']['result'].insert_one({"wfID" : wfID, "vulns" : vulns})
    return vulns

def main(argv):
    count = 0
    if argv.count == 0:
        count = db.count_documents({})
    else:
        count = argv.count
    for workflow in db.find({}).limit(count):
        if not results.find_one({"wfID": workflow.get("_id")}):
            print(workflow['name'])
            _id = workflow.get("_id")
            _repo_name = workflow.get("name")
            processed = dict()
            _wf_list = []
            for item in workflow.get("workflows"):
                _wf_list.append((item['name'], wfExtractor.extract_workflow(item['yaml'])))
            for name, item in _wf_list:
                if 'jobs' not in item.keys():
                    continue
                if name not in processed.keys():
                    processed.update({name: []})
                processed[name].append(item)  
            analyze(processed, _id, _repo_name)
        else:
            print("Already analyzed")
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A wrapper aroud GHAST to just analize workflows from a MongoDB database and store the results')
    parser.add_argument("--count", dest='count', type=int, default=1000, help="Number of workflows to analyze (0 for all)")

    args = parser.parse_args()
    main(args)