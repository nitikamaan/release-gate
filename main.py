from fastapi import FastAPI
from typing import Any

app = FastAPI()


@app.post("/release-gate")
def release_gate(data: dict[str, Any]):

    violations = []

    workflow = data["workflow"]
    image = data["image"]

    # 1. Permissions
    required_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }

    if workflow.get("permissions") != required_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull request trigger
    if data["event"] == "pull_request":
        if workflow["trigger"] != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

        if not workflow["testsPassed"]:
            violations.append("TESTS_INCOMPLETE")

        if not workflow["matrixComplete"]:
            if "TESTS_INCOMPLETE" not in violations:
                violations.append("TESTS_INCOMPLETE")

        if workflow["failFast"] is not False:
            if "TESTS_INCOMPLETE" not in violations:
                violations.append("TESTS_INCOMPLETE")

    # 3. Action pinning
    for action in workflow["actions"]:
        if action["owner"] != "actions":
            ref = action["ref"]

            if not (
                len(ref) == 40
                and all(c in "0123456789abcdef" for c in ref)
            ):
                violations.append("MUTABLE_ACTION")
                break

    # 4. Image checks
    if not image["multiStage"]:
        violations.append("SINGLE_STAGE_IMAGE")

    if image["runsAsRoot"]:
        violations.append("ROOT_RUNTIME")

    if image["secretMode"] in ["arg", "copy"]:
        violations.append("SECRET_IN_LAYER")

    if image["criticalVulnerabilities"] != 0:
        violations.append("CRITICAL_CVE")

    if not image["digestPinned"]:
        violations.append("UNPINNED_IMAGE")

    # 5. Production checks
    if data["target"] == "production":

        if (
            data["event"] != "push"
            or workflow["trigger"] != "push"
            or data["ref"] != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # Remove duplicate violations
    violations = list(dict.fromkeys(violations))

    decision = "promote" if len(violations) == 0 else "block"

    return {
        "decision": decision,
        "violations": violations
    }