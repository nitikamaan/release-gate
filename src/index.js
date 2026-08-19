const REQUIRED_PERMISSIONS = {
  contents: "read",
  packages: "write",
  "id-token": "none"
};

const SHA_REGEX = /^[0-9a-f]{40}$/;

function response(decision, violations) {
  return new Response(
    JSON.stringify({
      decision,
      violations
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json"
      }
    }
  );
}

function isObject(value) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value);
}

function checkPermissions(workflow) {
  const permissions = workflow.permissions;

  if (!isObject(permissions)) {
    return "EXCESS_PERMISSION";
  }

  const keys = Object.keys(permissions);

  if (keys.length !== 3) {
    return "EXCESS_PERMISSION";
  }

  if (
    permissions.contents !== "read" ||
    permissions.packages !== "write" ||
    permissions["id-token"] !== "none"
  ) {
    return "EXCESS_PERMISSION";
  }

  return null;
}

function checkPullRequest(body) {
  if (body.event === "pull_request") {
    if (body.workflow.trigger !== "pull_request") {
      return "UNSAFE_PR_TRIGGER";
    }

    if (
      body.workflow.testsPassed !== true ||
      body.workflow.matrixComplete !== true ||
      body.workflow.failFast !== false
    ) {
      return "TESTS_INCOMPLETE";
    }
  }

  return null;
}

function checkTests(body) {
  if (
    body.workflow.testsPassed !== true ||
    body.workflow.matrixComplete !== true ||
    body.workflow.failFast !== false
  ) {
    return "TESTS_INCOMPLETE";
  }

  return null;
}

function checkActions(workflow) {
  if (!Array.isArray(workflow.actions)) {
    return null;
  }

  for (const action of workflow.actions) {
    if (!isObject(action)) {
      return "MUTABLE_ACTION";
    }

    if (
      typeof action.owner !== "string" ||
      typeof action.name !== "string" ||
      typeof action.ref !== "string"
    ) {
      return "MUTABLE_ACTION";
    }

    if (action.owner === "actions") {
      continue;
    }

    if (!SHA_REGEX.test(action.ref)) {
      return "MUTABLE_ACTION";
    }
  }

  return null;
}

function checkImage(image) {
  if (image.multiStage !== true) {
    return "SINGLE_STAGE_IMAGE";
  }

  if (image.runsAsRoot !== false) {
    return "ROOT_RUNTIME";
  }

  if (
    image.secretMode !== "none" &&
    image.secretMode !== "buildkit"
  ) {
    return "SECRET_IN_LAYER";
  }

  if (image.criticalVulnerabilities !== 0) {
    return "CRITICAL_CVE";
  }

  if (image.digestPinned !== true) {
    return "UNPINNED_IMAGE";
  }

  return null;
}

function checkProduction(body) {
  if (body.target !== "production") {
    return [];
  }

  const violations = [];

  if (
    body.event !== "push" ||
    body.ref !== "refs/heads/main"
  ) {
    violations.push("INVALID_PRODUCTION_REF");
  }

  if (body.workflow.environmentApproval !== true) {
    violations.push("APPROVAL_REQUIRED");
  }

  return violations;
}

function validateBasicSchema(body) {
  if (!isObject(body)) {
    return false;
  }

  if (
    body.target !== "preview" &&
    body.target !== "production"
  ) {
    return false;
  }

  if (
    body.event !== "pull_request" &&
    body.event !== "push"
  ) {
    return false;
  }

  if (typeof body.ref !== "string") {
    return false;
  }

  if (!isObject(body.workflow)) {
    return false;
  }

  if (!isObject(body.workflow.permissions)) {
    return false;
  }

  if (
    typeof body.workflow.testsPassed !== "boolean" ||
    typeof body.workflow.matrixComplete !== "boolean" ||
    typeof body.workflow.failFast !== "boolean"
  ) {
    return false;
  }

  if (!isObject(body.image)) {
    return false;
  }

  if (
    typeof body.image.multiStage !== "boolean" ||
    typeof body.image.runsAsRoot !== "boolean" ||
    typeof body.image.secretMode !== "string" ||
    typeof body.image.criticalVulnerabilities !== "number" ||
    typeof body.image.digestPinned !== "boolean"
  ) {
    return false;
  }

  return true;
}

function evaluate(body) {
  const violations = [];

  /*
   * Permissions
   */
  const permissionViolation =
    checkPermissions(body.workflow);

  if (permissionViolation !== null) {
    violations.push(permissionViolation);
  }

  /*
   * Pull request safety
   */
  const prViolation =
    checkPullRequest(body);

  if (prViolation !== null) {
    violations.push(prViolation);
  }

  /*
   * Complete testing
   *
   * Tests are required for every release.
   */
  const testViolation =
    checkTests(body);

  if (
    testViolation !== null &&
    !violations.includes(testViolation)
  ) {
    violations.push(testViolation);
  }

  /*
   * Action pinning
   */
  const actionViolation =
    checkActions(body.workflow);

  if (actionViolation !== null) {
    violations.push(actionViolation);
  }

  /*
   * Container hardening
   */
  const imageViolation =
    checkImage(body.image);

  if (imageViolation !== null) {
    violations.push(imageViolation);
  }

  /*
   * Production requirements
   */
  const productionViolations =
    checkProduction(body);

  for (const violation of productionViolations) {
    violations.push(violation);
  }

  if (violations.length === 0) {
    return response("promote", []);
  }

  return response("block", violations);
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (
      request.method !== "POST" ||
      url.pathname !== "/release-gate"
    ) {
      return response("block", ["UNSAFE_PR_TRIGGER"]);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return response("block", ["TESTS_INCOMPLETE"]);
    }

    /*
     * The supplied task defines only the listed violation codes.
     * Therefore malformed top-level data is treated as a policy failure.
     */
    if (!validateBasicSchema(body)) {
      return response("block", ["TESTS_INCOMPLETE"]);
    }

    return evaluate(body);
  }
};