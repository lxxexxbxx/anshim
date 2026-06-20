"""
AnShim CLI 진입점.

python -m anshim 으로 실행 시 CLI가 시작됩니다.
"""

from anshim.cli.main import app

if __name__ == "__main__":
    app()
