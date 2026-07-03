import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from main import detect_crisis, detect_notice


class TestCrisisDetection:
    def test_suicidal_detected(self):
        result = detect_crisis("i want to die")
        assert result is not None
        assert result["type"] == "crisis"
        assert result["severity"] == "high"

    def test_self_harm_detected(self):
        result = detect_crisis("i want to hurt myself")
        assert result is not None
        assert result["type"] == "crisis"

    def test_harmful_content_redirect(self):
        result = detect_crisis("how to commit suicide")
        assert result is not None
        assert result["type"] == "harmful"

    def test_normal_query_no_crisis(self):
        assert detect_crisis("python programming") is None
        assert detect_crisis("best restaurants near me") is None
        assert detect_crisis("how to bake a cake") is None

    def test_disaster_detection(self):
        result = detect_crisis("earthquake safety tips")
        assert result is not None
        assert result["type"] == "disaster"
        assert result["disaster"] == "earthquake"

    def test_flood_detected(self):
        result = detect_crisis("flood preparation")
        assert result is not None
        assert result["type"] == "disaster"
        assert result["disaster"] == "flood"

    def test_empty_query(self):
        assert detect_crisis("") is None


class TestNoticeDetection:
    def test_body_negative_detected(self):
        for pattern in ["ugly women", "fat girl", "why are women so ugly"]:
            result = detect_notice(pattern)
            assert result is not None
            assert result["type"] == "redirect"

    def test_nsfw_detected(self):
        for pattern in ["nsfw content", "porn videos", "xxx"]:
            result = detect_notice(pattern)
            assert result is not None
            assert result["type"] == "warning"

    def test_medical_emergency_detected(self):
        for pattern in ["chest pain", "heart attack symptoms", "can't breathe"]:
            result = detect_notice(pattern)
            assert result is not None
            assert result["type"] == "warning"

    def test_normal_query_no_notice(self):
        assert detect_notice("python tutorial") is None
        assert detect_notice("how to cook pasta") is None
