import subprocess
import sys
import os

# Redirect to Streamlit Dashboard
if __name__ == "__main__":
    gui_path = os.path.join(os.path.dirname(__file__), "gui.py")
    
    # Check if streamlit is installed
    try:
        import streamlit
    except ImportError:
        print("Streamlit not found. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "streamlit"], check=True)

    print(f"Launching Lilith-Zero Dashboard...")
    
    # Run streamlit
    cmd = [sys.executable, "-m", "streamlit", "run", gui_path]
    
    try:
        # Replace current process with streamlit run
        # On windows execv is tricky, subprocess is safer
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error launching dashboard: {e}")
