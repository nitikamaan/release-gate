function isObject(value) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value);
}

function checkPermissions(workflow, violations) {
  const permissions = workflow.permissions;

  if (!isObject(permissions)) {
    violations.push("EXCESS_PERMISSION");
    return;
  }

  const keys = Object.keys(permissions);

  if (
    keys.length !== 3 ||
    permissions.contents !== "read" ||
    permissions.packages !== "write" ||
    permissions["id-token"] !== "none"
  ) {
    violations.push("EXCESS_PERMISSION");
  }
}

function checkPullRequest(body, violations) {
  if (body.event === "pull_request") {
    if (body.workflow.trigger !== "pull_request") {
      violations.push("UNSAFE_PR_TRIGGER");
    }
  }
}

function checkTests(workflow, violations) {
  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push("TESTS_INCOMPLETE");
  }
}

function checkActions(workflow, violations) {
  if (!Array.isArray(workflow.actions)) {
    violations.push("MUTABLE_ACTION");
    return;
  }

  const shaRegex = /^[0-9a-f]{40}$/;

  for (const action of workflow.actions) {
    if (!isObject(action)) {
      violations.push("MUTABLE_ACTION");
      continue;
    }

    if (
      typeof action.owner !== "string" ||
      typeof action.name !== "string" ||
      typeof action.ref !== "string"
    ) {
      violations.push("MUTABLE_ACTION");
      continue;
    }

    if (action.owner !== "actions" && !shaRegex.test(action.ref)) {
      violations.push("MUTABLE_ACTION");
    }
  }
}

function checkImage(image, violations) {
  if (image.multiStage !== true) {
    violations.push("SINGLE_STAGE_IMAGE");
  }

  if (image.runsAsRoot !== false) {
    violations.push("ROOT_RUNTIME");
  }

  if (
    image.secretMode !== "none" &&
    image.secretMode !== "buildkit"
  ) {
    violations.push("SECRET_IN_LAYER");
  }

  if (image.criticalVulnerabilities !== 0) {
    violations.push("CRITICAL_CVE");
  }

  if (image.digestPinned !== true) {
    violations.push("UNPINNED_IMAGE");
  }
}

function checkProduction(body, violations) {
  if (body.target !== "production") {
    return;
  }

  if (
    body.event !== "push" ||
    body.ref !== "refs/heads/main"
  ) {
    violations.push("INVALID_PRODUCTION_REF");
  }

  if (body.workflow.environmentApproval !== true) {
    violations.push("APPROVAL_REQUIRED");
  }
}

function validBasicSchema(body) {
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

  if (!Array.isArray(body.workflow.actions)) {
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

function json(decision, violations) {
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

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (
      request.method !== "POST" ||
      url.pathname !== "/release-gate"
    ) {
      return json("block", ["TESTS_INCOMPLETE"]);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json("block", ["TESTS_INCOMPLETE"]);
    }

    if (!validBasicSchema(body)) {
      return json("block", ["TESTS_INCOMPLETE"]);
    }

    const violations = [];

    checkPermissions(body.workflow, violations);

    checkPullRequest(body, violations);

    checkTests(body.workflow, violations);

    checkActions(body.workflow, violations);

    checkImage(body.image, violations);

    checkProduction(body, violations);

    if (violations.length === 0) {
      return json("promote", []);
    }

    return json("block", violations);
  }
};