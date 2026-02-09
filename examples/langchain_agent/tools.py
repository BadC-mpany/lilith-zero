# Copyright 2026 BadCompany
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
