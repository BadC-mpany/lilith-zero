
try:
    from pydantic import BaseModel as V2BaseModel, create_model as v2_create_model
    print(f"Pydantic V2 BaseModel: {V2BaseModel}")
except ImportError:
    print("Pydantic V2 not found")

try:
    from pydantic.v1 import BaseModel as V1BaseModel, create_model as v1_create_model
    print(f"Pydantic V1 BaseModel: {V1BaseModel}")
except ImportError:
    print("Pydantic V1 namespace not found")

try:
    from langchain_core.tools import StructuredTool
    from langchain_core.pydantic_v1 import BaseModel as LC_V1_BaseModel
    print(f"LangChain Core V1 Model: {LC_V1_BaseModel}")
except ImportError:
    print("LangChain Core V1 utils not available")

try:
    from langchain_core.runnables.utils import IsLocalBaseModel
    # Just checking what they use
    pass
except ImportError:
    pass

# Create a test tool
async def test_func(x: int): return x

def test_v2():
    try:
        model = v2_create_model("Test", x=(int, ...))
        print(f"V2 Model bases: {model.__mro__}")
        t = StructuredTool.from_function(
            coroutine=test_func,
            name="test_v2",
            description="test",
            args_schema=model
        )
        print("Success with V2 model")
    except Exception as e:
        print(f"Failed with V2 model: {e}")

def test_v1():
    try:
        model = v1_create_model("Test", x=(int, ...))
        print(f"V1 Model bases: {model.__mro__}")
        t = StructuredTool.from_function(
            coroutine=test_func,
            name="test_v1",
            description="test",
            args_schema=model
        )
        print("Success with V1 model")
    except Exception as e:
        print(f"Failed with V1 model: {e}")

print("\n--- Testing V2 ---")
test_v2()

print("\n--- Testing V1 ---")
test_v1()
