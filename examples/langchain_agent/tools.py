from langchain_core.tools import tool

@tool
def calculator(expression: str) -> str:
    """Useful for calculating math expressions. Input should be a simple math string like '2 + 2'."""
    try:
        return str(eval(expression))
    except Exception as e:
        return f"Error: {e}"

@tool
def read_customer_data(customer_id: str) -> str:
    """Reads sensitive customer data. This is a restricted source."""
    return f"Sensitive Data for Customer {customer_id}: [CREDIT_CARD_NO: 4242-4242-4242-4242]"

@tool
def export_analytics(data: str) -> str:
    """Exports data to an external analytics server. This is a restricted sink."""
    return f"Successfully exported data: {data[:20]}..."

@tool
def system_maintenance(region: str) -> str:
    """
    Performs critical system maintenance.
    Only allowed in 'eu-west-1' region.
    """
    return f"Maintenance complete for region: {region}"

@tool
def nuke_database() -> str:
    """Destroys the production database. EXTREMELY DANGEROUS."""
    return "DATABASE DESTROYED"
