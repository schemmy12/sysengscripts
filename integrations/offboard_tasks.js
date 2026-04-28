const PROPS = PropertiesService.getScriptProperties();
const BOT_TOKEN = PROPS.getProperty("SLACK_BOT_TOKEN");
const SIGNING_SECRET = PROPS.getProperty("SLACK_SIGNING_SECRET");
const OW_BEARER = PROPS.getProperty("OW_BEARER_TOKEN");
const OW_ROUTER_URL = PROPS.getProperty("OW_ROUTER_URL");

// ── Entry point ──────────────────────────────────────────────
function doPost(e) {
  const contentType = (e.postData && e.postData.type) || e.contentType || "";
  const params = e.parameter || {};

  if (contentType.includes("application/json")) {
    return handleInteractivity(JSON.parse(e.postData.contents));
  }

  if (params.command === "/offboard-tasks") {
    return handleSlashCommand(params);
  }

  if (params.payload) {
    return handleInteractivity(JSON.parse(params.payload));
  }

  return ContentService.createTextOutput(
    JSON.stringify({ response_action: "clear" })
  ).setMimeType(ContentService.MimeType.JSON);
}

// ── Slash command → open modal ───────────────────────────────
function handleSlashCommand(params) {
  const triggerId = params.trigger_id;
  const modal = buildModal();

  UrlFetchApp.fetch("https://slack.com/api/views.open", {
    method: "post",
    headers: {
      "Authorization": "Bearer " + BOT_TOKEN,
      "Content-Type": "application/json"
    },
    payload: JSON.stringify({ trigger_id: triggerId, view: modal })
  });

  return okResponse();
}

// ── Modal submission → route to correct Okta Workflow ────────
function handleInteractivity(payload) {
  if (payload.type === "block_actions") {
    return handleBlockAction(payload);
  }
  if (payload.type !== "view_submission") return okResponse();

  const values         = payload.view.state.values;
  const action         = values.action_block.action_select.selected_option.value;
  const userEmail      = values.user_email_block.user_email_input.value;
  const delegateEmail  = values.delegate_email_block?.delegate_email_input?.value || "";
  const forwardToEmail = values.delegate_email_block?.delegate_email_input?.value || "";
  const oooMessage     = values.ooo_message_block?.ooo_message_input?.value || "";
  const oooSubject     = values.ooo_subject_block?.ooo_subject_input?.value || "";
  const oooEndDate     = values.ooo_end_date_block?.ooo_end_date_input?.selected_date || null;
  const slackUserId    = payload.user.id;

  try {
    const workflowResponse = callOktaWorkflow(OW_ROUTER_URL, {
        action,
        userEmail,
        delegateEmail,
        forwardToEmail,
        oooMessage,
        oooSubject,
        oooEndDate
});

  sendSlackMessage(
  slackUserId,
  buildSlackResponse(action, userEmail, workflowResponse, delegateEmail)
);

  } catch (err) {
    sendSlackMessage(slackUserId, ":x: Something went wrong: " + err.message);
  }

  return ContentService.createTextOutput(
    JSON.stringify({ response_action: "clear" })
  ).setMimeType(ContentService.MimeType.JSON);
}

function handleBlockAction(payload) {
  const selectedAction =
    payload.actions?.[0]?.selected_option?.value || "";

  const currentValues = payload.view?.state?.values || {};
  const modal = buildModal(selectedAction, currentValues);

  UrlFetchApp.fetch("https://slack.com/api/views.update", {
    method: "post",
    headers: {
      "Authorization": "Bearer " + BOT_TOKEN,
      "Content-Type": "application/json"
    },
    payload: JSON.stringify({
      view_id: payload.view.id,
      hash: payload.view.hash,
      view: modal
    }),
    muteHttpExceptions: true
  });

  return okResponse();
}

// ── Call Okta Workflows API endpoint ────────────────────────
function callOktaWorkflow(url, body) {
  const res = UrlFetchApp.fetch(url, {
    method: "post",
    headers: {
      "Authorization": "Bearer " + OW_BEARER,
      "Content-Type": "application/json"
    },
    payload: JSON.stringify(body),
    muteHttpExceptions: true
  });

  const code = res.getResponseCode();
  const text = res.getContentText();

  if (code < 200 || code > 299) {
    throw new Error("Okta Workflow returned " + code + ": " + text);
  }

  try {
    return text ? JSON.parse(text) : {};
  } catch (e) {
    return { raw: text };
  }
}

// ── Send a message back to Slack ─────────────────────────────
function sendSlackMessage(channel, text) {
  UrlFetchApp.fetch("https://slack.com/api/chat.postMessage", {
    method: "post",
    headers: {
      "Authorization": "Bearer " + BOT_TOKEN,
      "Content-Type": "application/json"
    },
    payload: JSON.stringify({ channel, text })
  });
}

// ── Build the Block Kit modal ────────────────────────────────
function buildModal(selectedAction = "", currentValues = {}) {
  const selectedOptionMap = {
  ooo: {
    text: { type: "plain_text", text: "📭  Set out of office (OOO)" },
    value: "ooo"
  },
  delegate: {
    text: { type: "plain_text", text: "📬  Delegate inbox to manager" },
    value: "delegate"
  },
  forward: {
    text: { type: "plain_text", text: "📨  Forward emails to inbox" },
    value: "forward"
  },
  all: {
    text: { type: "plain_text", text: "⚡  Run ALL Actions" },
    value: "all"
  },
  delete_delegate: {
    text: { type: "plain_text", text: "🗑️  Remove delegate" },
    value: "delete_delegate"
  },
  delete_sendas: {
    text: { type: "plain_text", text: "🗑️  Remove send-as alias" },
    value: "delete_sendas"
  },
  list_delegates: {
    text: { type: "plain_text", text: "📋  List delegates" },
    value: "list_delegates"
  },
  add_sendas: {
    text: { type: "plain_text", text: "➕  Add send-as alias" },
    value: "add_sendas"
},
  remove_ooo: {
    text: { type: "plain_text", text: "🧹  Remove out of office" },
    value: "remove_ooo"
},
};

  const blocks = [
  {
    type: "context",
    elements: [{ type: "mrkdwn", text: "Select the task(s) to run for the departing user. All actions are logged in Okta Workflows." }]
  },
  {
    type: "input",
    block_id: "action_block",
    dispatch_action: true,
    label: { type: "plain_text", text: "Action" },
    element: Object.assign(
      {
        type: "static_select",
        action_id: "action_select",
        placeholder: { type: "plain_text", text: "Choose an action..." },
        options: [
        selectedOptionMap.ooo,
        selectedOptionMap.delegate,
        selectedOptionMap.forward,
        selectedOptionMap.delete_delegate,
        selectedOptionMap.delete_sendas,
        selectedOptionMap.list_delegates,
        selectedOptionMap.list_google_group_members,
        selectedOptionMap.add_sendas,
        selectedOptionMap.remove_ooo,
        selectedOptionMap.all
]
      },
      selectedAction ? { initial_option: selectedOptionMap[selectedAction] } : {}
    )
  }
];

  if (selectedAction) {
  blocks.push({
    type: "input",
    block_id: "user_email_block",
    label: { type: "plain_text", text: "Departing user email" },
    element: {
      type: "plain_text_input",
      action_id: "user_email_input",
      initial_value: currentValues.user_email_block?.user_email_input?.value || "",
      placeholder: { type: "plain_text", text: "john.doe@company.com" }
    }
  });
}
  // show second email field for actions that need it
  if (["delegate", "forward", "all", "delete_delegate", "delete_sendas", "add_sendas", "list_google_group_members"].includes(selectedAction)) {
  const emailFieldText =
    selectedAction === "forward"
      ? {
          label: "Forward-to email",
          hint: "Used for email forwarding.",
          placeholder: "recipient@company.com"
        }
      : selectedAction === "delegate"
      ? {
          label: "Manager / delegate email",
          hint: "Used for mailbox delegation.",
          placeholder: "manager@company.com"
        }
      : selectedAction === "delete_delegate"
      ? {
          label: "Delegate email to remove",
          hint: "Used to remove mailbox delegation.",
          placeholder: "delegate@company.com"
        }
      : selectedAction === "delete_sendas"
      ? {
          label: "Send-as alias to remove",
          hint: "Used to remove a send-as alias.",
          placeholder: "alias@company.com"
        }
      : selectedAction === "add_sendas"
      ? {
          label: "Send-as alias to add",
          hint: "Used to add a send-as alias.",
          placeholder: "alias@company.com"
        }
      : selectedAction === "list_google_group_members"
      ? {
          label: "Google Group email",
          hint: "Used to look up members of a Google Group.",
          placeholder: "group@company.com"
        }
      : {
          label: "Manager / delegate / forward-to email",
          hint: "Used for delegation and email forwarding.",
          placeholder: "manager@company.com"
        };

  blocks.push({
    type: "input",
    block_id: "delegate_email_block",
    label: { type: "plain_text", text: emailFieldText.label },
    hint: { type: "plain_text", text: emailFieldText.hint },
    optional: false,
    element: {
      type: "plain_text_input",
      action_id: "delegate_email_input",
      initial_value: currentValues.delegate_email_block?.delegate_email_input?.value || "",
      placeholder: { type: "plain_text", text: emailFieldText.placeholder }
    }
  });
}

  // show OOO fields for ooo and all
  if (["ooo", "all"].includes(selectedAction)) {
    blocks.push(
      {
        type: "input",
        block_id: "ooo_subject_block",
        label: { type: "plain_text", text: "OOO subject line" },
        optional: true,
        element: {
          type: "plain_text_input",
          action_id: "ooo_subject_input",
          initial_value: currentValues.ooo_subject_block?.ooo_subject_input?.value || "",
          placeholder: { type: "plain_text", text: "Out of Office - John Doe" }
        }
      },
      {
        type: "input",
        block_id: "ooo_message_block",
        label: { type: "plain_text", text: "OOO message" },
        optional: true,
        element: {
          type: "plain_text_input",
          action_id: "ooo_message_input",
          multiline: true,
          initial_value: currentValues.ooo_message_block?.ooo_message_input?.value || "",
          placeholder: { type: "plain_text", text: "Thank you for your email..." }
        }
      },
      {
        type: "input",
        block_id: "ooo_end_date_block",
        label: { type: "plain_text", text: "OOO end date" },
        optional: true,
        element: {
          type: "datepicker",
          action_id: "ooo_end_date_input",
          initial_date: currentValues.ooo_end_date_block?.ooo_end_date_input?.selected_date,
          placeholder: { type: "plain_text", text: "Select a date" }
        }
      }
    );
  }

  return {
    type: "modal",
    callback_id: "offboard_modal",
    title: { type: "plain_text", text: "Offboarding Tasks" },
    submit: { type: "plain_text", text: "Run" },
    close:  { type: "plain_text", text: "Cancel" },
    blocks
  };
}
// ── Confirmation message builder ─────────────────────────────
function buildConfirmation(action, userEmail) {
  const labels = {
    ooo:      "✅ *Out of office set* for " + userEmail,
    delegate: "✅ *Inbox delegated* for " + userEmail,
    forward:  "✅ *Email forwarding enabled* for " + userEmail,
    all:      "✅ *All actions launched* for " + userEmail,
    delete_delegate: "✅ *Delegate removed* for " + userEmail,
    delete_sendas: "✅ *Send-as alias removed* for " + userEmail,
    list_delegates: "✅ *Delegate list requested* for " + userEmail,
    add_sendas: "✅ *Send-as alias added* for " + userEmail,
    remove_ooo: "✅ *Out of office removed* for " + userEmail,
    list_google_group_members: "✅ *Google Group members retrieved* for " + userEmail
  };
  return (labels[action] || "✅ Task completed") + "\n_Logged in Okta Workflows execution history._";
}


function buildSlackResponse(action, userEmail, workflowResponse, secondEmail) {
  if (action === "list_google_group_members") {
    const groupEmail = secondEmail || userEmail;
    const members = workflowResponse.members || workflowResponse.groupMembers || [];

    if (!members.length) {
      return "📋 *Google Group Members* — " + groupEmail + "\n\nNo members found.";
    }

    const lines = members.slice(0, 25).map(m => {
      if (typeof m === "string") return "• " + m;
      return "• " + (m.email || m.primaryEmail || JSON.stringify(m));
    });

    let message =
      "📋 *Google Group Members* — " + groupEmail + "\n\n" +
      "*Count:* " + members.length + "\n\n" +
      lines.join("\n");

    if (members.length > 25) {
      message += "\n\n_Showing first 25 of " + members.length + " members._";
    }

    return message;
  }

  return buildConfirmation(action, userEmail);
}


// ── Helpers ──────────────────────────────────────────────────
function okResponse() {
  return ContentService.createTextOutput("").setMimeType(ContentService.MimeType.TEXT);
}