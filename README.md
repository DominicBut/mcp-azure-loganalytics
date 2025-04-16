# Azure Log Analytics MCP Server

This project implements an MCP server in Python that leverages Azure services to provide tools and prompts for log analysis. The server performs the following functions:

- **Azure Activity Logs Retrieval:** Uses the Azure Monitor Management client to obtain Azure activity logs within a specified time range.
- **Log Analytics Query:** Uses the Azure Monitor Query client to run Kusto Query Language (KQL) queries against a Log Analytics workspace.
- **LLM Prompts:** Exposes two prompts to help with common log analysis tasks:
  - **Analyze Log Errors:** Generates a prompt for an LLM to analyze error patterns in raw log data.
  - **Summarize Activity Logs:** Creates a prompt for summarizing the activity logs.

## Prerequisites

- Python 3.8+
- An Azure subscription with appropriate permissions
- Azure credentials (using any method supported by `DefaultAzureCredential`)
- Environment variables set for:
  - `AZURE_SUBSCRIPTION_ID`
  - `AZURE_LOG_ANALYTICS_WORKSPACE_ID`


