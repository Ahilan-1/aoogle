import os
import sys
import json
import tempfile

os.environ['DISABLE_BACKGROUND_SCHEDULER'] = '1'

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from main import app, DataManager, _load_json, _save_json, DATA_FILE, ImprovedSearch
from main import detect_crisis, detect_notice, SearchBlocker, SearchIntent
from main import get_info_box, CRISIS_RESOURCES, DISASTER_KEYWORDS
from main import BODY_NEGATIVE_PATTERNS, NSFW_CONTENT_PATTERNS, MEDICAL_HELP_PATTERNS
from main import QUERY_INTENTS, DOMAIN_AUTHORITY


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def runner():
    return app.test_cli_runner()


@pytest.fixture(autouse=True)
def clean_data():
    original_file = DATA_FILE
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
        json.dump({"reports": [], "blacklist": {}, "total_searches": 0, "celebration": "", "announcement": ""}, f)
    import main as m
    m.DATA_FILE = temp_path
    m.data_manager = DataManager()
    yield
    try:
        os.unlink(temp_path)
    except:
        pass
    m.DATA_FILE = original_file
    m.data_manager = DataManager()
