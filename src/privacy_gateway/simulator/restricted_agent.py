from dataclasses import dataclass


TOOLS = {
    "public_status": {
        "restricted": False,
        "result": "All synthetic public services are operational.",
    },

    "private_customer_lookup": {
        "restricted": True,
        "result": (
            "Synthetic customer secret: "
            "CUSTOMER-DEMO-5519"
        ),
    },
}


@dataclass
class AgentResult:
    requested_tool: str
    tool_exists: bool
    tool_restricted: bool
    executed: bool
    final_response: str
    leaked: bool
    protection_enabled: bool


class RestrictedAgentSimulator:
    """
    Synthetic restricted-agent simulator.

    Tools and results are completely local and fake.
    No external service or real action is executed.
    """

    def run(
        self,
        requested_tool: str,
        protection_enabled: bool,
    ) -> AgentResult:

        tool = TOOLS.get(requested_tool)

        if tool is None:
            return AgentResult(
                requested_tool=requested_tool,
                tool_exists=False,
                tool_restricted=False,
                executed=False,
                final_response="[ERROR: unknown tool]",
                leaked=False,
                protection_enabled=protection_enabled,
            )

        restricted = tool["restricted"]

        # Protected mode checks authorization before execution.
        if protection_enabled and restricted:
            executed = False
            final_response = (
                "[BLOCKED: unauthorized tool invocation]"
            )

        else:
            # Vulnerable mode executes the requested tool.
            executed = True
            final_response = tool["result"]

        leaked = (
            "CUSTOMER-DEMO-5519"
            in final_response
        )

        return AgentResult(
            requested_tool=requested_tool,
            tool_exists=True,
            tool_restricted=restricted,
            executed=executed,
            final_response=final_response,
            leaked=leaked,
            protection_enabled=protection_enabled,
        )
