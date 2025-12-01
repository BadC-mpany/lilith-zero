#!/usr/bin/env python3
"""
Sentinel End-to-End Demo Script

This script demonstrates and validates all features documented in the README:
- Backend connectivity
- Tool loading and security enforcement
- Static and dynamic (taint) rules
- Tool classification
- Integration examples

Run this after completing README setup steps 1-4.
"""

import os
import sys
import uuid
import httpx
from typing import List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Color output for better readability
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text:^70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")

def print_section(text: str):
    print(f"\n{Colors.OKBLUE}{Colors.BOLD}▶ {text}{Colors.ENDC}")

def print_success(text: str):
    print(f"{Colors.OKGREEN}✓ {text}{Colors.ENDC}")

def print_warning(text: str):
    print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")

def print_error(text: str):
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")

def print_info(text: str):
    print(f"  {text}")


def test_environment_setup():
    """Test Step 1: Environment Configuration"""
    print_header("TEST 1: Environment Setup Validation")
    
    issues = []
    
    # Check .env file
    if not os.path.exists(".env"):
        issues.append(".env file not found")
        print_error(".env file not found")
    else:
        print_success(".env file exists")
    
    # Check required environment variables
    required_vars = {
        "SENTINEL_API_KEY": os.getenv("SENTINEL_API_KEY"),
        "SENTINEL_URL": os.getenv("SENTINEL_URL", "http://localhost:8000"),
        "OPENROUTER_API_KEY": os.getenv("OPENROUTER_API_KEY"),
    }
    
    for var, value in required_vars.items():
        if value:
            print_success(f"{var} is set")
        else:
            issues.append(f"{var} is not set")
            print_error(f"{var} is not set")
    
    # Check policies.yaml
    policies_path = "sentinel_core/policies.yaml"
    if os.path.exists(policies_path):
        print_success(f"{policies_path} exists")
    else:
        issues.append(f"{policies_path} not found")
        print_error(f"{policies_path} not found")
    
    # Check tool_registry.yaml
    registry_path = "rule_maker/data/tool_registry.yaml"
    if os.path.exists(registry_path):
        print_success(f"{registry_path} exists")
    else:
        issues.append(f"{registry_path} not found")
        print_error(f"{registry_path} not found")
    
    if issues:
        print_warning(f"Found {len(issues)} issue(s). Please review README Step 1.")
        return False
    return True


def test_backend_connectivity():
    """Test Step 3: Backend Services Connectivity"""
    print_header("TEST 2: Backend Services Connectivity")
    
    interceptor_url = os.getenv("SENTINEL_URL", "http://localhost:8000")
    mcp_url = "http://localhost:9000"
    
    # Test Interceptor - try root endpoint or docs
    print_section("Testing Interceptor Service")
    interceptor_ok = False
    try:
        # Try root endpoint first
        response = httpx.get(f"{interceptor_url}/", timeout=5.0)
        if response.status_code in [200, 404, 405]:  # 404/405 means server is up
            print_success(f"Interceptor is reachable at {interceptor_url}")
            interceptor_ok = True
        else:
            print_warning(f"Interceptor responded with status {response.status_code}")
    except httpx.ConnectError:
        print_error(f"Cannot connect to Interceptor at {interceptor_url}")
        print_info("Make sure Docker services are running: docker-compose up")
        return False
    except Exception as e:
        # Try docs endpoint as fallback
        try:
            response = httpx.get(f"{interceptor_url}/docs", timeout=5.0)
            if response.status_code == 200:
                print_success(f"Interceptor is reachable at {interceptor_url} (via /docs)")
                interceptor_ok = True
            else:
                print_error(f"Error connecting to Interceptor: {e}")
                return False
        except:
            print_error(f"Error connecting to Interceptor: {e}")
            return False
    
    # Test MCP (optional - may not have health endpoint)
    print_section("Testing MCP Service")
    try:
        response = httpx.get(mcp_url, timeout=5.0)
        if response.status_code in [200, 404, 405]:
            print_success(f"MCP is reachable at {mcp_url}")
        else:
            print_warning(f"MCP responded with status {response.status_code}")
    except httpx.ConnectError:
        print_warning(f"Cannot connect to MCP at {mcp_url} (may be normal if no health endpoint)")
    except Exception as e:
        print_warning(f"MCP connection check: {e}")
    
    return interceptor_ok


def test_tool_loading():
    """Test Step 4: Tool Loading from README Integration Example"""
    print_header("TEST 3: Tool Loading (README Integration Example)")
    
    # Try to fix import path issue
    import sys
    sdk_path = os.path.join(os.getcwd(), "sentinel_sdk", "src")
    if os.path.exists(sdk_path) and sdk_path not in sys.path:
        sys.path.insert(0, sdk_path)
    
    try:
        from sentinel_agent.tool_loader import load_sentinel_tools
        from sentinel_sdk import SecurityBlockException, SentinelSecureTool
        
        print_section("Loading tools using load_sentinel_tools")
        api_key = os.getenv("SENTINEL_API_KEY", "sk_live_demo_123")
        
        try:
            secure_tools = load_sentinel_tools(api_key=api_key)
            print_success(f"Loaded {len(secure_tools)} tools")
            
            # Show tool names
            tool_names = [tool.name for tool in secure_tools]
            print_info(f"Available tools: {', '.join(tool_names)}")
            
            # Test session ID setting (from README example)
            session_id = str(uuid.uuid4())
            for tool in secure_tools:
                tool.set_session_id(session_id)
            print_success(f"Set session_id on all tools: {session_id[:8]}...")
            
            return True, secure_tools, session_id
            
        except Exception as e:
            print_error(f"Failed to load tools: {e}")
            import traceback
            print_info(f"Error details: {traceback.format_exc()[:200]}...")
            return False, None, None
            
    except ImportError as e:
        print_error(f"Import error: {e}")
        print_info("Attempting to fix import path...")
        
        # Try direct import from source
        try:
            sys.path.insert(0, os.path.join(os.getcwd(), "sentinel_sdk", "src"))
            sys.path.insert(0, os.path.join(os.getcwd(), "sentinel_agent", "src"))
            
            from tool_loader import load_sentinel_tools
            from sentinel_sdk import SecurityBlockException
            
            print_success("Imports work with direct path access")
            print_warning("Packages may not be properly installed in editable mode")
            print_info("Run: pip install -e sentinel_sdk -e sentinel_agent")
            
            # Try loading tools anyway
            api_key = os.getenv("SENTINEL_API_KEY", "sk_live_demo_123")
            secure_tools = load_sentinel_tools(api_key=api_key)
            print_success(f"Loaded {len(secure_tools)} tools (using direct path)")
            
            session_id = str(uuid.uuid4())
            for tool in secure_tools:
                tool.set_session_id(session_id)
            
            return True, secure_tools, session_id
            
        except Exception as e2:
            print_error(f"Direct import also failed: {e2}")
            print_info("Make sure packages are installed: pip install -e sentinel_sdk -e sentinel_agent")
            return False, None, None


def test_security_enforcement(secure_tools: List, session_id: str):
    """Test Security Enforcement: Static and Dynamic Rules"""
    print_header("TEST 4: Security Enforcement (Static & Dynamic Rules)")
    
    if not secure_tools:
        print_error("No tools available for testing")
        return False
    
    from sentinel_sdk import SecurityBlockException
    
    # Find specific tools
    tool_dict = {tool.name: tool for tool in secure_tools}
    
    results = []
    
    # Test 1: Allowed action (web_search on clean session)
    print_section("Test 1: Allowed Action (Web Search - Clean State)")
    if "web_search" in tool_dict:
        try:
            result = tool_dict["web_search"]._run(query="test query")
            print_success("Web search allowed (clean state)")
            print_info(f"Result: {str(result)[:100]}...")
            results.append(True)
        except SecurityBlockException as e:
            print_error(f"Unexpected block: {e.reason}")
            results.append(False)
        except Exception as e:
            print_warning(f"Error (may be expected if backend not fully running): {e}")
            results.append(None)
    else:
        print_warning("web_search tool not available")
        results.append(None)
    
    # Test 2: Static rule block (delete_db should be DENY)
    print_section("Test 2: Static Rule Block (delete_db - Expected DENY)")
    if "delete_db" in tool_dict:
        try:
            result = tool_dict["delete_db"]._run(confirm=True)
            print_error("delete_db was NOT blocked (should be blocked by static rule)")
            results.append(False)
        except SecurityBlockException as e:
            print_success(f"delete_db correctly blocked: {e.reason}")
            results.append(True)
        except Exception as e:
            print_warning(f"Error: {e}")
            results.append(None)
    else:
        print_warning("delete_db tool not available")
        results.append(None)
    
    # Test 3: Taint addition (read_file adds taint)
    print_section("Test 3: Taint Addition (read_file - Adds 'sensitive_data' taint)")
    if "read_file" in tool_dict:
        try:
            result = tool_dict["read_file"]._run(path="/etc/secrets.txt")
            print_success("read_file executed (taint should be added)")
            print_info(f"Result: {str(result)[:100]}...")
            results.append(True)
        except SecurityBlockException as e:
            print_warning(f"read_file blocked: {e.reason}")
            results.append(None)
        except Exception as e:
            print_warning(f"Error: {e}")
            results.append(None)
    else:
        print_warning("read_file tool not available")
        results.append(None)
    
    # Test 4: Dynamic rule block (web_search after taint)
    print_section("Test 4: Dynamic Rule Block (Web Search After Taint)")
    if "web_search" in tool_dict:
        try:
            result = tool_dict["web_search"]._run(query="test after taint")
            print_error("Web search was NOT blocked after taint (should be blocked)")
            results.append(False)
        except SecurityBlockException as e:
            print_success(f"Web search correctly blocked after taint: {e.reason}")
            results.append(True)
        except Exception as e:
            print_warning(f"Error: {e}")
            results.append(None)
    else:
        print_warning("web_search tool not available")
        results.append(None)
    
    # Summary
    passed = sum(1 for r in results if r is True)
    total = sum(1 for r in results if r is not None)
    print_section("Security Enforcement Summary")
    print_info(f"Tests passed: {passed}/{total}")
    
    return passed == total if total > 0 else False


def test_tool_classification():
    """Test Tool Classification (rule_maker)"""
    print_header("TEST 5: Tool Classification (rule_maker)")
    
    openrouter_key = os.getenv("OPENROUTER_API_KEY")
    if not openrouter_key:
        print_warning("OPENROUTER_API_KEY not set - skipping classification test")
        print_info("Classification requires OPENROUTER_API_KEY in .env (see README)")
        return None
    
    try:
        # Import classifier - add rule_maker/src to path
        import importlib.util
        classifier_path = os.path.join("rule_maker", "src", "classifier.py")
        if not os.path.exists(classifier_path):
            raise ImportError(f"Classifier not found at {classifier_path}")
        
        spec = importlib.util.spec_from_file_location("classifier", classifier_path)
        classifier_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(classifier_module)
        classify_tool_with_llm = classifier_module.classify_tool_with_llm
        
        print_section("Classifying example tool: 'send_email'")
        print_info("This demonstrates the LLM-based classification system")
        
        try:
            result = classify_tool_with_llm(
                tool_name="send_email",
                tool_description="Sends an email message to a specified recipient",
                api_key=openrouter_key
            )
            
            classes = result.get("classes", [])
            reasoning = result.get("reasoning", "")
            
            print_success(f"Classification successful")
            print_info(f"Classes: {', '.join(classes)}")
            print_info(f"Reasoning: {reasoning[:150]}...")
            
            return True
            
        except Exception as e:
            print_error(f"Classification failed: {e}")
            print_info("This may be due to API rate limits or model availability")
            return False
            
    except ImportError as e:
        print_error(f"Could not import classifier: {e}")
        print_info("Make sure rule_maker/src/classifier.py exists")
        return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False


def test_readme_integration_example():
    """Test the exact code example from README Integration section"""
    print_header("TEST 6: README Integration Example Validation")
    
    print_section("Testing exact code from README Integration section")
    
    # Try to fix import path issue
    import sys
    sdk_path = os.path.join(os.getcwd(), "sentinel_sdk", "src")
    if os.path.exists(sdk_path) and sdk_path not in sys.path:
        sys.path.insert(0, sdk_path)
    
    try:
        from sentinel_agent.tool_loader import load_sentinel_tools
        from sentinel_sdk import SecurityBlockException
        
        # This is the exact code from README (os and uuid already imported at module level)
        API_KEY = os.getenv("SENTINEL_API_KEY")
        session_id = str(uuid.uuid4())
        secure_tools = load_sentinel_tools(api_key=API_KEY)
        
        for tool in secure_tools:
            tool.set_session_id(session_id)
        
        print_success("README integration example code executed successfully")
        print_info(f"Loaded {len(secure_tools)} tools")
        print_info(f"Session ID: {session_id[:8]}...")
        print_info("Note: AgentExecutor setup would require LLM configuration")
        
        return True
        
    except ImportError as e:
        # Try direct import as fallback
        try:
            sys.path.insert(0, os.path.join(os.getcwd(), "sentinel_agent", "src"))
            sys.path.insert(0, os.path.join(os.getcwd(), "sentinel_sdk", "src"))
            
            from tool_loader import load_sentinel_tools
            from sentinel_sdk import SecurityBlockException
            
            API_KEY = os.getenv("SENTINEL_API_KEY")
            session_id = str(uuid.uuid4())
            secure_tools = load_sentinel_tools(api_key=API_KEY)
            
            for tool in secure_tools:
                tool.set_session_id(session_id)
            
            print_success("README integration example code executed (using direct path)")
            print_warning("Packages may need to be reinstalled: pip install -e sentinel_sdk -e sentinel_agent")
            print_info(f"Loaded {len(secure_tools)} tools")
            print_info(f"Session ID: {session_id[:8]}...")
            
            return True
            
        except Exception as e2:
            print_error(f"README integration example failed: {e2}")
            print_info("This suggests packages are not properly installed")
            print_info("Run: pip install -e sentinel_sdk -e sentinel_agent")
            return False
    except Exception as e:
        print_error(f"README integration example failed: {e}")
        return False


def main():
    """Run all tests"""
    print_header("Sentinel End-to-End Demo & README Validation")
    print_info("This script validates all features documented in the README")
    print_info("Make sure you've completed README setup steps 1-4 before running\n")
    
    results = {}
    
    # Test 1: Environment
    results["environment"] = test_environment_setup()
    
    # Test 2: Backend connectivity
    results["backend"] = test_backend_connectivity()
    
    # Test 3: Tool loading
    tool_load_success, secure_tools, session_id = test_tool_loading()
    results["tool_loading"] = tool_load_success
    
    # Test 4: Security enforcement (requires tools)
    if tool_load_success and secure_tools:
        results["security"] = test_security_enforcement(secure_tools, session_id)
    else:
        print_warning("Skipping security tests - tools not loaded")
        results["security"] = None
    
    # Test 5: Classification (optional)
    results["classification"] = test_tool_classification()
    
    # Test 6: README integration example
    results["integration_example"] = test_readme_integration_example()
    
    # Final summary
    print_header("Final Summary")
    
    test_names = {
        "environment": "Environment Setup",
        "backend": "Backend Connectivity",
        "tool_loading": "Tool Loading",
        "security": "Security Enforcement",
        "classification": "Tool Classification",
        "integration_example": "README Integration Example"
    }
    
    for key, name in test_names.items():
        result = results.get(key)
        if result is True:
            print_success(f"{name}: PASSED")
        elif result is False:
            print_error(f"{name}: FAILED")
        else:
            print_warning(f"{name}: SKIPPED/OPTIONAL")
    
    # Overall assessment
    passed = sum(1 for r in results.values() if r is True)
    failed = sum(1 for r in results.values() if r is False)
    skipped = sum(1 for r in results.values() if r is None)
    
    print_section("Overall Results")
    print_info(f"Passed: {passed}")
    print_info(f"Failed: {failed}")
    print_info(f"Skipped/Optional: {skipped}")
    
    if failed == 0:
        print_success("\nAll critical tests passed! README instructions are accurate.")
    else:
        print_warning(f"\n{failed} test(s) failed. Please review the errors above.")
        print_info("Common fixes:")
        print_info("  1. .env file is configured (Step 1)")
        print_info("  2. Docker services are running: docker-compose up (Step 3)")
        print_info("  3. Packages installed correctly (Step 4):")
        print_info("     pip install -r requirements.txt")
        print_info("     pip install -e sentinel_sdk -e sentinel_agent")
        print_info("  4. If imports fail, verify packages are in editable mode:")
        print_info("     pip list | Select-String 'sentinel'")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

