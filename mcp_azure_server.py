# mcp_azure_server.py
import os
import asyncio
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from azure.mgmt.monitor import MonitorManagementClient
from mcp.server.fastmcp import FastMCP
from mcp.server.stdio import stdio_server

# Create an MCP server instance with a descriptive name.
mcp = FastMCP("AzureLogAnalyticsServer")

# Initialize Azure credentials.
# DefaultAzureCredential aggregates several authentication methods.
azure_credential = DefaultAzureCredential()

# Retrieve required Azure configuration from environment variables.
log_analytics_workspace_id = os.environ.get("AZURE_LOG_ANALYTICS_WORKSPACE_ID")
subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")

# Create clients for querying logs and activity logs.
logs_client = LogsQueryClient(credential=azure_credential)
monitor_client = MonitorManagementClient(credential=azure_credential, subscription_id=subscription_id)

# ----------------------------------------
# Tool: Retrieve Azure Activity Logs
# ----------------------------------------
@mcp.tool()
def get_activity_logs(start_time: str, end_time: str) -> str:
    """
    Retrieve Azure activity logs within a given time range.
    
    Parameters:
      - start_time (str): ISO formatted start time (e.g. "2025-04-15T00:00:00Z").
      - end_time (str): ISO formatted end time.
      
    Returns:
      A text summary of the activity log entries.
    """
    try:
        # Build filter for activity logs; the filter syntax depends on Azure’s API.
        # Note: This is a basic example. In production, the filter may need to be refined.
        filter_str = f"eventTimestamp ge '{start_time}' and eventTimestamp le '{end_time}'"
        logs_paged = monitor_client.activity_logs.list(filter=filter_str)
        
        log_entries = []
        for log in logs_paged:
            # Extract and format relevant log information.
            # The properties available depend on the log event type.
            timestamp = log.event_timestamp
            operation = getattr(log, "operation_name", "N/A")
            status = getattr(log, "status", {}).get("value", "N/A")
            log_entries.append(f"{timestamp} - {operation} - {status}")
            
        return "\n".join(log_entries) if log_entries else "No activity logs found."
    except Exception as e:
        return f"Error retrieving activity logs: {str(e)}"

# ----------------------------------------
# Tool: Query Log Analytics via KQL
# ----------------------------------------
@mcp.tool()
def query_log_analytics(query: str, timespan: str = "PT1H") -> str:
    """
    Query the Azure Log Analytics workspace using a Kusto Query Language query.
    
    Parameters:
      - query (str): The KQL query string.
      - timespan (str): The period to query (default "PT1H" for the past hour).
      
    Returns:
      A string representation of the query results.
    """
    try:
        response = logs_client.query_workspace(
            workspace_id=log_analytics_workspace_id,
            query=query,
            timespan=timespan,
        )
        result_str = ""
        if response.tables:
            table = response.tables[0]
            # Prepare a header from column names.
            header = "\t".join(col.name for col in table.columns)
            result_str += header + "\n"
            # Append each row of the result.
            for row in table.rows:
                result_str += "\t".join(str(item) for item in row) + "\n"
        return result_str if result_str else "No data returned."
    except Exception as e:
        return f"Error querying Log Analytics: {str(e)}"

# ----------------------------------------
# Prompt: Analyze Log Errors
# ----------------------------------------
@mcp.prompt()
def analyze_log_errors(log_data: str) -> str:
    """
    Generate a prompt to analyze error patterns in log data.
    
    Parameters:
      - log_data (str): Raw log data to analyze.
      
    Returns:
      A prompt string intended for an LLM to review the log data and identify issues.
    """
    return (
        "Please analyze the following log data and identify any error patterns or recurring issues:\n\n"
        f"{log_data}\n\n"
        "Summarize potential causes and offer recommendations."
    )

# ----------------------------------------
# Prompt: Summarize Activity Logs
# ----------------------------------------
@mcp.prompt()
def summarize_activity_logs(log_data: str) -> str:
    """
    Generate a prompt to summarize Azure activity logs.
    
    Parameters:
      - log_data (str): The raw activity logs as a string.
      
    Returns:
      A prompt string that instructs an LLM to summarize the logs.
    """
    return (
        "Please summarize the following Azure activity logs and highlight any unusual events or performance issues:\n\n"
        f"{log_data}\n\n"
        "Provide a brief summary and any recommendations for further investigation."
    )

# ----------------------------------------
# Run the server using stdio transport
# ----------------------------------------
if __name__ == "__main__":
    async def main():
        async with stdio_server() as (read, write):
            # Create initialization options based on the MCP SDK.
            init_options = mcp.create_initialization_options()
            await mcp.run(read, write, init_options)
    
    asyncio.run(main())

