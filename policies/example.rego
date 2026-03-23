package allow_tool_call

# Default deny
default allow := false

# Allow tool calls only from active agents within their scope
allow if {
    input.agent_status == "active"
    input.tool_name in input.allowed_tools
}

# Time-based restrictions: only allow infra_apply during business hours
allow if {
    input.agent_id == "spiffe://domain/sre-bot"
    input.tool_name == "infra_apply"
    input.environment == "non-prod"
    time.clock(input.timestamp)[0] >= 9
    time.clock(input.timestamp)[0] < 17
}

# Deny specific high-risk tool combinations
deny if {
    input.tool_name == "delete_backup"
}

# Require human approval for financial transactions above threshold
require_human_approval if {
    input.tool_name == "execute_transaction"
    input.arguments.amount > 10000
}
