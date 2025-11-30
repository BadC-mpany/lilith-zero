"""
Quick test script for the classifier.
Run this to verify the classifier works correctly.

Usage:
    Ensure OPENROUTER_API_KEY is set in .env file, then:
    python rule_maker/test_classifier.py
"""

import os
from classifier import classify_tool_with_llm
from dotenv import load_dotenv

# Load from .env
load_dotenv()


def test_classifier():
    """Test the classifier with a few example tools"""
    
    # Check if API key is available
    if not os.getenv("OPENROUTER_API_KEY"):
        print("ERROR: OPENROUTER_API_KEY not set in .env file")
        return False
    
    test_tools = [
        ("get_time", "Returns the current system time in UTC"),
        ("send_slack_message", "Posts a message to a Slack channel"),
        ("execute_python", "Executes Python code in a sandbox"),
        ("read_user_profile", "Reads user profile data from database"),
        ("mask_credit_card", "Replaces credit card numbers with asterisks"),
    ]
    
    print("\n" + "="*80)
    print("CLASSIFIER TEST")
    print("="*80 + "\n")
    
    for tool_name, tool_desc in test_tools:
        print(f"🔍 Testing: {tool_name}")
        print(f"   Description: {tool_desc}")
        
        try:
            # API key and model loaded from .env automatically
            result = classify_tool_with_llm(
                tool_name=tool_name,
                tool_description=tool_desc,
                max_examples_per_class=2
            )
            
            print(f"   ✅ Classes: {', '.join(result['classes'])}")
            print(f"   💭 Reasoning: {result['reasoning'][:100]}...")
            print()
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            print()
            return False
    
    print("="*80)
    print("✅ All tests passed!")
    print("="*80)
    return True


if __name__ == "__main__":
    success = test_classifier()
    exit(0 if success else 1)

