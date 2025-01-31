import os
import re
import ruamel.yaml as yaml
from hashlib import sha256
import time
import json
import argparse
import semantic_version
import ruamel
from requests import get
from datetime import datetime
from pymongo.mongo_client import MongoClient

# get position of string ": name:" in a file
from typing import Dict, List

keys = os.getenv("ght", "NO_TOKEN").split("|")

event_rank = {
    "fork": 3,
    "issue_comment": 3,
    "issues": 3,
    "pull_request_comment": 3,
    "watch": 3,
    "pull_request": 2,
    "pull_request_target": 2,
    "pull_request_review": 1,
    "pull_request_review_comment": 1,
    "push": 1,
    "release": 1,
    "workflow_call": 1,
    "workflow_dispatch": 1,
    "workflow_run": 1,
}


def get_key() -> str:
    curr = keys.pop(0)
    keys.append(curr)
    return curr


def get_tags(repo):
    print(f"Getting tags for {repo}")
    with MongoClient() as client:
        item = client["ghast"]["repo_cache"].find_one({"repo": repo})
        if item:
            return item["tags"]
        api_url = "https://api.github.com/repos/" + repo + "/tags"
        req = get(api_url, headers={"Authorization": f"token {get_key()}"})
        if req.status_code == 200:
            tags = json.loads(req.text)
            entry = {"repo": repo, "tags": tags}
            client["ghast"]["repo_cache"].insert_one(entry)
        if req.status_code != 200:
            print("Error getting tags", req.status_code, req.text)
            await_limit()
            return get_tags(repo)
    tags = json.loads(req.text)
    return tags


def get_action_intel(action):
    print(f"Getting data for the action {action}")
    with MongoClient() as client:
        res = client["ghast"]["cache"].find_one({"name": action})
        if res:
            return res
        else:
            api_url = "https://api.github.com/repos/" + action + "/releases/latest"

            req = get(
                api_url,
                headers={"Authorization": f"token {get_key()}"},
            )
            if req.status_code == 200:
                res = json.loads(req.text)
                res["name"] = action
                client["ghast"]["cache"].insert_one(res)
                return res
            else:
                print(f"Waiting for rate limit... {req.status_code}, {req.content}")
                await_limit()
                return get_action_intel(action)


def get_position(file_name, string):
    indexes = []
    with open(file_name, "r") as f:
        for i, line in enumerate(f):
            if string in line:
                indexes.append(i + 1)
    return indexes


# Separate a string based on a patter similar to "#example\nname: example"
def separate_string(string):
    rex = r"___WORKFLOW END___\n"
    found = re.findall(rex, string)
    print(found)
    indx = []
    for e, i in enumerate(found):
        indx.append(
            (string.find(i), string.find(found[e + 1]) if e + 1 < len(found) else -1)
        )
    return indx


def extract_workflow(sample):
    output = dict()
    try:
        workflow = yaml.round_trip_load(sample)
    except ruamel.yaml.scanner.ScannerError:
        return output
    except ruamel.yaml.composer.ComposerError:
        return output
    if workflow is None:
        return output

    try:
        output["name"] = workflow.get("name")

        output["permissions"] = repr(workflow.get("permissions"))
        output["conditional"] = workflow.get("if")

        if isinstance(workflow["on"], str):
            output["events"] = {
                "type": workflow.get("on"),
                "security_rank": event_rank[workflow.get("on")],
            }
        elif isinstance(workflow["on"], list):
            output["events"] = [
                {
                    "type": workflow.get("on")[i],
                    "security_rank": event_rank[workflow.get("on")[i]],
                }
                for i in range(len(workflow["on"]))
            ]
        elif isinstance(workflow["on"], dict):
            output["events"] = []
            for event in workflow.get("on"):
                if isinstance(workflow.get("on")[event], dict):
                    output["events"].append(
                        {
                            "type": event,
                            "security_rank": event_rank[event],
                            "filters": [k for k in workflow.get("on")[event].keys()],
                        }
                    )
                else:
                    output["events"].append(
                        {"type": event, "security_rank": event_rank[event]}
                    )
        else:
            assert (
                False
            ), f'Unsupported type {type(workflow.get("on"))} for workflow.on field'

        jobs = workflow.get("jobs", dict())
        output["jobs"] = extract_jobs(jobs, True if workflow.get("if") else False)
    except:
        return output
    return output


def extract_jobs(jobs, conditional_wf):
    output = dict()

    for id, job in jobs.items():
        output[id] = dict()

        output[id]["name"] = job.get("name")
        output[id]["uses"] = job.get("uses")
        output[id]["conditional"] = job.get("if")
        output[id]["permissions"] = job.get("permissions")
        output[id]["steps"] = extract_steps(
            job.get("steps", []), True if job.get("if") else False, conditional_wf
        )

    return output


def extract_steps(steps, conditional_job, conditional_wf):
    output = []

    for i, step in enumerate(steps):
        item = dict()

        item["name"] = step.get("name")
        item["conditional"] = step.get("if")
        item["position"] = i + 1
        item["uses"] = step.get("uses", None)
        _run = step.get("run", None)
        item["security"] = {}
        if step.get("uses", None):
            item["security"].update(
                {"TP Actions Up-to-date": check_uses_version(item["uses"])}
            )
            # print(item['security'])
        if _run is not None:
            item["run"] = len(_run.split("\n"))
            item["run_hash"] = sha256(str.encode(_run)).hexdigest()
            item["security"] = {
                "runs": run_analyzer(step, conditional_wf, conditional_job)
            }
        else:
            item["run"] = 0
        output.append(item)

    return output


def perms_analyzer(wf):
    wf_name, wf_dict = wf
    if wf_dict["permissions"]:
        print(f"Workflow has permissions: {wf_dict['permissions']}")
    for job in wf_dict["jobs"].keys():
        if wf_dict["jobs"][job]["permissions"]:
            print(f"Job {job} has permissions: {wf_dict['jobs'][job]['permissions']}")


def run_analyzer(
    step: Dict[str, any], cond_wf: bool, cond_job: bool
) -> List[Dict[str, any]]:
    rex = r".*(\${{\s*github\.).*"
    ret = []
    if step["run"]:
        for i, l in enumerate(step["run"].split("\n")):
            if re.match(rex, l):
                if step.get("if", None) or cond_wf or cond_job:
                    ret.append({"position": i, "line": l, "conditional": True})
                    # print(f"Conditional direct run at job {job} @ step {step['name']}")
                else:
                    ret.append({"position": i, "line": l, "conditional": False})
                    # print(f"Direct run at job {job} @ step {step['name']}")
    return ret


def secret_analyzer(job: str, step: Dict[str, any]):
    secret_re = r".*(secrets\.).*"
    if step["run"]:
        for l in step["run"]:
            if re.match(secret_re, l):
                print(f"Secret appears at job {job} @ step {step['name']}")


def workflow_analyzer(wf):
    wf_name, wf_dict = wf
    for job in wf_dict["jobs"].keys():
        for step in wf_dict["jobs"][job]["steps"]:
            run_analyzer(
                job, step, wf_dict["conditional"], wf_dict["jobs"][job]["conditional"]
            )
            secret_analyzer(job, step)


def check_uses_version(action: str) -> bool:
    if action.split("@")[-1].replace("v", "") in ["master", "main"]:
        return True
    try:
        version = semantic_version.Version.coerce(
            action.split("@")[-1].replace("v", "")
        )
    except:
        version = action.split("@")[-1].replace("v", "")
    position = action.split("@")[0]
    data = get_action_intel(position)
    latest_version = str(data["tag_name"]).replace("v", "")
    try:
        latest_version = semantic_version.Version.coerce(latest_version)
        if latest_version.major == version.major:
            return True
        else:
            return version >= latest_version
    except:
        return latest_version == version


def get_status():
    api_url = "https://api.github.com/rate_limit"
    req = get(api_url, headers={"Authorization": "token f{TOKEN}"})
    try:
        return req.json().get("resources", {}).get("core", {}).get(
            "remaining", 0
        ), req.json().get("resources", {}).get("core", {}).get("reset", 60 * 60)
    except:
        return 0, 60 * 60


def await_limit():
    limit, until = get_status()
    if limit < 0:
        time.sleep(until - int(datetime.utcnow().timestamp()) + 10)


# if __name__ == "__main__":
#     wfs = []
#     print("Starting workflow analysis...")
#     with open(args.workflowfile, encoding='utf-8', errors="replace") as f:
#         dat = f.read()
#         for wf in dat.split("___WORKFLOW END___\n"):
#             # print(wf + "---------------------\n")
#             if wf != "":
#                 wf_name = wf.split("\n")[0].replace("#", "")
#                 if wf.find(u'\x04') > 0:
#                     print(wf[wf.find(u'\x04'):])
#                 wfs.append((wf_name, extract_workflow(wf)))
#                 print('\r' + str(len(wfs)))
#     wfs_dict = dict()
#     for w in wfs:
#         if 'jobs' not in w[1].keys():
#             continue
#         if w[0] not in wfs_dict.keys():
#             wfs_dict.update({w[0]: []})
#         wfs_dict[w[0]].append(w[1])
#     print(wfs_dict.keys())
#     with open(args.destination+"/savedDictWfs.dat", "wb") as f:
#         pickle.dump(wfs_dict, f)
