@echo off
echo Setting up SecAuditAI development environment...

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Install development dependencies
echo Installing development dependencies...
pip install -e .

REM Install Tree-sitter language parsers
echo Installing Tree-sitter language parsers...
python -c "import tree_sitter; tree_sitter.Language.build_library('build/my-languages.so', ['tree-sitter-python', 'tree-sitter-javascript', 'tree-sitter-java', 'tree-sitter-go'])"

REM Create configuration directory
echo Creating configuration directory...
if not exist "%USERPROFILE%\.secauditai" mkdir "%USERPROFILE%\.secauditai"

REM Initialize configuration
echo Initializing configuration...
secauditai init

echo Development environment setup complete!
echo To activate the virtual environment, run:
echo venv\Scripts\activate.bat 