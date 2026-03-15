import re
import yaml
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

EXEMPT_ROLE_NAMES = {"odb-developer-role", "odb-admin-role"}  # ← add as many as needed
BLOCKED_ACTION_PATTERN = re.compile(r"^odb:.*create.*", re.IGNORECASE)
_template_cache: dict = {}

DEBUG = True


def dbg(msg):
    if DEBUG:
        print(f">>> [CHI_POLICY_SERVICE_001] {msg}")


def _cfn_loader() -> yaml.SafeLoader:
    """SafeLoader that handles all CloudFormation intrinsic function tags."""
    loader = yaml.SafeLoader
    # Handle every !Tag as {"Tag": value} so !Ref X → {"Ref": "X"}
    def make_constructor(tag):
        def constructor(loader, node):
            if isinstance(node, yaml.ScalarNode):
                return {tag: loader.construct_scalar(node)}
            elif isinstance(node, yaml.SequenceNode):
                return {tag: loader.construct_sequence(node)}
            elif isinstance(node, yaml.MappingNode):
                return {tag: loader.construct_mapping(node)}
        return constructor

    cfn_tags = [
        "Ref", "Condition",
        "Fn::Base64", "Fn::Cidr", "Fn::FindInMap", "Fn::GetAtt",
        "Fn::GetAZs", "Fn::ImportValue", "Fn::Join", "Fn::Select",
        "Fn::Split", "Fn::Sub", "Fn::Transform", "Fn::If",
        "Fn::Equals", "Fn::Not", "Fn::And", "Fn::Or",
    ]
    for tag in cfn_tags:
        loader.add_constructor(f"!{tag}", make_constructor(tag))

    return loader


def _get_template_resources(file_path: str) -> dict:
    if file_path in _template_cache:
        dbg(f"cache hit for {file_path}")
        return _template_cache[file_path]
    try:
        with open(file_path) as f:
            template = yaml.load(f, Loader=_cfn_loader())
        _template_cache[file_path] = template.get("Resources", {})
        dbg(f"loaded template, resources: {list(_template_cache[file_path].keys())}")
    except Exception as e:
        dbg(f"ERROR loading template {file_path}: {e}")
        _template_cache[file_path] = {}
    return _template_cache[file_path]


class ODBCreateActionCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Privileged odb:create* actions must not be assigned to non-privileged roles",
            id="CHI_POLICY_SERVICE_001",
            categories=[CheckCategories.IAM],
            supported_resources=["AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"],
        )
        self.guideline = "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-iam-policies/iam-16-iam-policy-privileges-1"
        dbg("check registered")

    def scan_resource_conf(self, conf, **kwargs):
        dbg("--- scan_resource_conf called ---")
        properties = conf.get("Properties", {})

        file_path = properties.get("__file__")
        dbg(f"file_path from conf: {file_path}")

        if not file_path:
            dbg("WARNING: no __file__ found in conf — skipping role exemption check")
        else:
            template_resources = _get_template_resources(file_path)
            roles = properties.get("Roles", [])
            dbg(f"roles in policy: {roles}")

            exempt = self._all_roles_exempt(roles, template_resources)
            dbg(f"all roles exempt: {exempt}")

            if exempt:
                dbg("PASS — policy attached only to exempt roles")
                return CheckResult.PASSED

        for statement in properties.get("PolicyDocument", {}).get("Statement", []):
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                dbg(f"checking action: {action}")
                if isinstance(action, str) and BLOCKED_ACTION_PATTERN.match(action):
                    dbg(f"FAIL — blocked action matched: {action}")
                    return CheckResult.FAILED

        dbg("PASS — no blocked actions found")
        return CheckResult.PASSED

    def _all_roles_exempt(self, roles: list, template_resources: dict) -> bool:
        if not roles:
            dbg("no roles attached — not exempt")
            return False
        for role in roles:
            if isinstance(role, dict) and "Ref" in role:
                logical_id = role["Ref"]
                role_name = (
                    template_resources
                    .get(logical_id, {})
                    .get("Properties", {})
                    .get("RoleName")
                )
                dbg(f"Ref={logical_id} → RoleName={role_name} (exempt list={EXEMPT_ROLE_NAMES})")
                if role_name not in EXEMPT_ROLE_NAMES:  # ← was !=
                    dbg(f"role {logical_id} is NOT exempt")
                    return False
            else:
                dbg(f"role entry is not a Ref: {role} — not exempt")
                return False
        return True

check = ODBCreateActionCheck()