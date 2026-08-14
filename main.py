from fastapi import FastAPI

app = FastAPI()


@app.post("/release-gate")
def release_gate(data: dict):

    violations = []

    workflow = data["workflow"]
    image = data["image"]

    # Permissions
    if workflow.get("permissions") != {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }:
        violations.append("EXCESS_PERMISSION")

    # Pull request rules
    if data.get("event") == "pull_request":

        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

        if (
            workflow.get("testsPassed") is not True
            or workflow.get("matrixComplete") is not True
            or workflow.get("failFast") is not False
        ):
            violations.append("TESTS_INCOMPLETE")

    # Action pinning
    for action in workflow.get("actions", []):

        if action.get("owner") != "actions":

            ref = action.get("ref", "")

            if not (
                len(ref) == 40
                and all(c in "0123456789abcdef" for c in ref)
            ):
                violations.append("MUTABLE_ACTION")

    # Image rules
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") in ["arg", "copy"]:
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # Production rules
    if data.get("target") == "production":

        if (
            data.get("event") != "push"
            or workflow.get("trigger") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    violations = list(dict.fromkeys(violations))

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations
    }