# checkov/checks/CHI_POLICY_SERVICE_001.py
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

class OdbServicePrefixCheck(BaseResourceCheck):
    def __init__(self):
        name = "Do not allow odb:* service prefix in IAM policies"
        id = "CHI_POLICY_SERVICE_001"
        categories = [CheckCategories.IAM]
        supported_resources = [
            "AWS::IAM::Policy",
            "AWS::IAM::ManagedPolicy",
            "AWS::IAM::Role"
        ]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # Handle both Policy and Role (inline policies)
        policy_doc = conf.get("Properties", {}).get("PolicyDocument", {})
        statements = policy_doc.get("Statement", [])

        for statement in statements:
            actions = statement.get("Action", [])
            # Normalize to list
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if isinstance(action, str) and action.lower().startswith("odb:"):
                    return CheckResult.FAILED

        return CheckResult.PASSED

check = OdbServicePrefixCheck()