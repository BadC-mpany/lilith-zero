from langchain_core.pydantic_v1 import BaseModel, Field

# It's best practice to define the input schema for each tool.
# This tells the LangChain agent executor exactly what arguments to expect
# and how to format them, preventing positional argument errors.

# if we want to add more tools, can this be automatized? like get this from MCP store?

class WebSearchInput(BaseModel):
    """Input for the web_search tool."""
    query: str = Field(description="The search query string.")

class ReadFileInput(BaseModel):
    """Input for the read_file tool."""
    path: str = Field(description="The file path to read from.")

class DeleteDbInput(BaseModel):
    """Input for the delete_db tool."""
    confirm: bool = Field(description="Confirmation flag to proceed with deletion. Must be True.")

# A dictionary to easily map tool names to their schemas
TOOL_SCHEMAS = {
    "web_search": WebSearchInput,
    "read_file": ReadFileInput,
    "delete_db": DeleteDbInput,
}
