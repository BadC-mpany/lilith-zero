$env:LILITH_LOG_LEVEL = "info" 
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
pushd $scriptDir
python agent.py
popd
